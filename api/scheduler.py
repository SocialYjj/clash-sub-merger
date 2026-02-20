"""
Scheduler API
Subscription auto-update scheduler endpoints
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.dependencies import verify_session
from core.database import load_config, save_config
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


# ==================== API Endpoints ====================

@router.get("/presets")
@handle_api_errors
def get_cron_presets(_: bool = Depends(verify_session)):
    """Get available cron presets"""
    from scheduler_service import CRON_PRESETS
    return {"presets": CRON_PRESETS}


@router.post("/validate-cron")
@handle_api_errors
def validate_cron_expression(data: dict, _: bool = Depends(verify_session)):
    """Validate cron expression and return next run time"""
    cron_expr = data.get('cron_expr', '').strip()
    
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
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    if sub.get('type') == 'local':
        raise HTTPException(status_code=400, detail="Local subscriptions cannot be scheduled")
    
    from scheduler_service import get_scheduler, get_cron_description
    scheduler = get_scheduler()
    
    # Remove existing job if any
    task_id = f"sub_refresh_{sub_id}"
    scheduler.remove_job(task_id)
    
    if data.cron_expr:
        # Validate and add new job
        try:
            from apscheduler.triggers.cron import CronTrigger
            trigger = CronTrigger.from_crontab(data.cron_expr)
            
            scheduler.add_job(
                task_id,
                data.cron_expr,
                srv.refresh_subscription_job,
                sub_id
            )
            
            job_info = scheduler.get_job_info(task_id)
            next_run = job_info["next_run"].timestamp() if job_info and job_info.get("next_run") else None
            
            sub['cron_expr'] = data.cron_expr
            sub['next_update'] = int(next_run) if next_run else None
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {str(e)}")
    else:
        sub['cron_expr'] = None
        sub['next_update'] = None
    
    save_config(config)
    
    return {
        "status": "success",
        "cron_expr": sub.get('cron_expr'),
        "description": get_cron_description(sub.get('cron_expr')) if sub.get('cron_expr') else None,
        "next_update": sub.get('next_update')
    }


@router.delete("/subscriptions/{sub_id}")
@handle_api_errors
def remove_subscription_schedule(sub_id: str, _: bool = Depends(verify_session)):
    """Remove subscription's schedule"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    from scheduler_service import get_scheduler
    scheduler = get_scheduler()
    
    task_id = f"sub_refresh_{sub_id}"
    scheduler.remove_job(task_id)
    
    sub['cron_expr'] = None
    sub['next_update'] = None
    save_config(config)
    
    return {"status": "success"}


@router.get("/jobs")
@handle_api_errors
def list_scheduled_jobs(_: bool = Depends(verify_session)):
    """List all scheduled jobs"""
    from scheduler_service import get_scheduler
    scheduler = get_scheduler()
    jobs = scheduler.list_jobs()
    return {"jobs": jobs, "count": len(jobs)}
