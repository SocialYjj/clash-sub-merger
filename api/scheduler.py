"""
Scheduler API
Subscription auto-update scheduler endpoints
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.dependencies import verify_session
from core.database import load_config, update_config
from helpers import handle_api_errors
from logger_config import get_logger
from services.subscription_refresh_lock import subscription_write_slot

logger = get_logger(__name__)
router = APIRouter()

# Lazy import server module
_server_module = None


def _get_server():
    global _server_module
    if _server_module is None:
        import server as srv
        _server_module = srv
    return _server_module


# ==================== Data Models ====================

class ScheduleUpdate(BaseModel):
    cron_expr: Optional[str] = None


class CronValidationRequest(BaseModel):
    cron_expr: str = ''


# ==================== API Endpoints ====================

@router.get("/presets")
@handle_api_errors
def get_cron_presets(_: bool = Depends(verify_session)):
    """Get available cron presets"""
    from scheduler_service import CRON_PRESETS
    return {"presets": CRON_PRESETS}


@router.post("/validate-cron")
@handle_api_errors
def validate_cron_expression(data: CronValidationRequest, _: bool = Depends(verify_session)):
    """Validate cron expression and return next run time"""
    cron_expr = data.cron_expr.strip()
    
    if not cron_expr:
        return {"valid": False, "error": "Cron expression is empty"}
    
    try:
        from apscheduler.triggers.cron import CronTrigger
        from datetime import datetime
        
        trigger = CronTrigger.from_crontab(cron_expr)
        next_run = trigger.get_next_fire_time(None, datetime.now())
        
        if next_run:
            # Format as readable string
            next_run_str = next_run.strftime("%Y-%m-%d %H:%M:%S")
            return {
                "valid": True,
                "next_run": next_run_str,
                "timestamp": int(next_run.timestamp())
            }
        else:
            return {"valid": False, "error": "Cannot calculate next run time"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


@router.get("/subscriptions/{sub_id}")
@handle_api_errors
def get_subscription_schedule(sub_id: str, _: bool = Depends(verify_session)):
    """Get subscription's schedule"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    from scheduler_service import get_cron_description
    cron_expr = sub.get('cron_expr')
    
    return {
        "cron_expr": cron_expr,
        "description": get_cron_description(cron_expr) if cron_expr else None,
        "next_update": sub.get('next_update')
    }


def _set_subscription_schedule(sub_id: str, cron_expression: Optional[str]) -> dict:
    """Keep the persisted cron expression and the in-memory job consistent."""
    srv = _get_server()
    from scheduler_service import get_scheduler

    scheduler = get_scheduler()
    task_id = f"sub_refresh_{sub_id}"
    requested_cron = cron_expression.strip() if cron_expression else None

    if requested_cron:
        from apscheduler.triggers.cron import CronTrigger
        CronTrigger.from_crontab(requested_cron)

    current_config = load_config()
    current_subscription = next(
        (candidate for candidate in current_config.get('subscriptions', []) if candidate['id'] == sub_id),
        None,
    )
    if not current_subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if current_subscription.get('type') == 'local':
        raise HTTPException(status_code=400, detail="Local subscriptions cannot be scheduled")

    previous_cron = current_subscription.get('cron_expr')
    subscription_enabled = current_subscription.get('enabled', True)

    def restore_previous_job() -> None:
        scheduler.remove_job(task_id)
        if previous_cron and subscription_enabled:
            scheduler.add_job(task_id, previous_cron, srv.refresh_subscription_job, sub_id)

    next_update = None
    if requested_cron and subscription_enabled:
        job_id = scheduler.add_job(
            task_id,
            requested_cron,
            srv.refresh_subscription_job,
            sub_id,
        )
        if not job_id:
            restore_previous_job()
            raise HTTPException(status_code=400, detail="Scheduler rejected the subscription job")

        job_info = scheduler.get_job_info(task_id)
        if not job_info or not job_info.get('next_run'):
            restore_previous_job()
            raise HTTPException(status_code=400, detail="Scheduler did not return a next run time")
        next_update = int(job_info['next_run'].timestamp())
    else:
        scheduler.remove_job(task_id)

    def apply_schedule_update(config: dict) -> dict:
        sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
        if not sub:
            raise HTTPException(status_code=404, detail="Subscription not found")
        sub['cron_expr'] = requested_cron
        sub['next_update'] = next_update
        return {
            "cron_expr": sub.get('cron_expr'),
            "next_update": sub.get('next_update'),
        }

    try:
        return update_config(apply_schedule_update)
    except Exception:
        restore_previous_job()
        raise


@router.put("/subscriptions/{sub_id}")
@handle_api_errors
def update_subscription_schedule(sub_id: str, data: ScheduleUpdate, _: bool = Depends(verify_session)):
    """Update a subscription schedule."""
    from scheduler_service import get_cron_description

    with subscription_write_slot(sub_id):
        saved_schedule = _set_subscription_schedule(sub_id, data.cron_expr)

    return {
        "status": "success",
        "cron_expr": saved_schedule.get('cron_expr'),
        "description": (
            get_cron_description(saved_schedule.get('cron_expr'))
            if saved_schedule.get('cron_expr')
            else None
        ),
        "next_update": saved_schedule.get('next_update'),
    }


@router.delete("/subscriptions/{sub_id}")
@handle_api_errors
def remove_subscription_schedule(sub_id: str, _: bool = Depends(verify_session)):
    """Remove a subscription schedule."""
    with subscription_write_slot(sub_id):
        _set_subscription_schedule(sub_id, None)
    return {"status": "success"}


@router.get("/jobs")
@handle_api_errors
def list_scheduled_jobs(_: bool = Depends(verify_session)):
    """List all scheduled jobs"""
    from scheduler_service import get_scheduler
    scheduler = get_scheduler()
    jobs = scheduler.list_jobs()
    return {"jobs": jobs, "count": len(jobs)}
