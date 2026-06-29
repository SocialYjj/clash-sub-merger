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


@router.put("/subscriptions/{sub_id}")
@handle_api_errors
def update_subscription_schedule(sub_id: str, data: ScheduleUpdate, _: bool = Depends(verify_session)):
    """Update subscription's schedule"""
    srv = _get_server()
    from scheduler_service import get_scheduler, get_cron_description
    scheduler = get_scheduler()
    task_id = f"sub_refresh_{sub_id}"

    # Validate cron expression BEFORE saving config or touching scheduler
    if data.cron_expr:
        from apscheduler.triggers.cron import CronTrigger
        CronTrigger.from_crontab(data.cron_expr)  # raises on invalid

    # Save config first (scheduler ops happen after, so config and scheduler stay consistent)
    def apply_schedule_update(config: dict) -> dict:
        sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
        if not sub:
            raise HTTPException(status_code=404, detail="Subscription not found")

        if sub.get('type') == 'local':
            raise HTTPException(status_code=400, detail="Local subscriptions cannot be scheduled")

        sub['cron_expr'] = data.cron_expr or None
        sub['next_update'] = None  # will be filled after scheduler add_job
        return {
            "cron_expr": sub.get('cron_expr'),
            "next_update": None
        }

    result = update_config(apply_schedule_update)

    # Now update the scheduler (config is already saved)
    try:
        scheduler.remove_job(task_id)
    except Exception:
        pass  # job may not exist

    if data.cron_expr:
        try:
            scheduler.add_job(
                task_id,
                data.cron_expr,
                srv.refresh_subscription_job,
                sub_id
            )
            job_info = scheduler.get_job_info(task_id)
            next_run = job_info["next_run"].timestamp() if job_info and job_info.get("next_run") else None

            # Update next_update in config
            if next_run:
                def update_next_run(config: dict) -> dict:
                    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
                    if sub:
                        sub['next_update'] = int(next_run)
                        return {"next_update": int(next_run)}
                    return {}
                update_config(update_next_run)
                result['next_update'] = int(next_run)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Scheduler error: {str(e)}")

    return {
        "status": "success",
        "cron_expr": result.get('cron_expr'),
        "description": get_cron_description(result.get('cron_expr')) if result.get('cron_expr') else None,
        "next_update": result.get('next_update')
    }


@router.delete("/subscriptions/{sub_id}")
@handle_api_errors
def remove_subscription_schedule(sub_id: str, _: bool = Depends(verify_session)):
    """Remove subscription's schedule"""
    from scheduler_service import get_scheduler
    scheduler = get_scheduler()
    task_id = f"sub_refresh_{sub_id}"

    def remove_schedule(config: dict):
        sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
        if not sub:
            raise HTTPException(status_code=404, detail="Subscription not found")

        scheduler.remove_job(task_id)
        sub['cron_expr'] = None
        sub['next_update'] = None

    update_config(remove_schedule)
    
    return {"status": "success"}


@router.get("/jobs")
@handle_api_errors
def list_scheduled_jobs(_: bool = Depends(verify_session)):
    """List all scheduled jobs"""
    from scheduler_service import get_scheduler
    scheduler = get_scheduler()
    jobs = scheduler.list_jobs()
    return {"jobs": jobs, "count": len(jobs)}
