"""
Scheduler Service Module
Provides cron-based task scheduling using APScheduler.
"""

import re
from datetime import datetime
from typing import Optional, Dict, Callable, Any
from threading import RLock

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.job import Job


class SchedulerManager:
    """
    Manages scheduled tasks using APScheduler.
    Supports cron expressions for subscription updates and speed tests.
    """
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.jobs: Dict[str, str] = {}  # {task_id: job_id}
        self._lock = RLock()
        self._started = False
        self._callbacks: Dict[str, Callable] = {}  # Store callbacks for tasks
    
    def start(self):
        """Start the scheduler"""
        if not self._started:
            self.scheduler.start()
            self._started = True
            print("Scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if self._started:
            self.scheduler.shutdown(wait=False)
            self._started = False
            print("Scheduler stopped")
    
    def is_running(self) -> bool:
        """Check if scheduler is running"""
        return self._started and self.scheduler.running
    
    @staticmethod
    def clean_cron_expression(cron_expr: str) -> str:
        """
        Clean and validate cron expression.
        Removes extra whitespace and validates format.
        
        Standard cron format: minute hour day month weekday
        Example: "0 */6 * * *" = every 6 hours
        """
        if not cron_expr:
            return ""
        
        # Remove leading/trailing whitespace
        cleaned = cron_expr.strip()
        
        # Replace multiple spaces with single space
        cleaned = re.sub(r'\s+', ' ', cleaned)
        
        return cleaned
    
    @staticmethod
    def validate_cron_expression(cron_expr: str) -> tuple[bool, str]:
        """
        Validate a cron expression.
        
        Returns:
            (is_valid, error_message)
        """
        if not cron_expr:
            return False, "Cron expression is empty"
        
        cleaned = SchedulerManager.clean_cron_expression(cron_expr)
        parts = cleaned.split(' ')
        
        if len(parts) != 5:
            return False, f"Cron expression must have 5 parts (minute hour day month weekday), got {len(parts)}"
        
        try:
            # Try to create a trigger to validate
            CronTrigger.from_crontab(cleaned)
            return True, ""
        except Exception as e:
            return False, str(e)
    
    def get_next_run_time(self, cron_expr: str) -> Optional[datetime]:
        """
        Calculate next run time for a cron expression.
        
        Returns:
            Next run datetime or None if invalid
        """
        cleaned = self.clean_cron_expression(cron_expr)
        if not cleaned:
            return None
        
        try:
            trigger = CronTrigger.from_crontab(cleaned)
            return trigger.get_next_fire_time(None, datetime.now())
        except Exception as e:
            print(f"Failed to parse cron expression '{cron_expr}': {e}")
            return None
    
    def add_job(
        self,
        task_id: str,
        cron_expr: str,
        func: Callable,
        *args,
        **kwargs
    ) -> Optional[str]:
        """
        Add a scheduled job.
        
        Args:
            task_id: Unique identifier for this task
            cron_expr: Cron expression (minute hour day month weekday)
            func: Function to execute
            *args, **kwargs: Arguments to pass to the function
        
        Returns:
            Job ID or None if failed
        """
        with self._lock:
            cleaned = self.clean_cron_expression(cron_expr)
            if not cleaned:
                print(f"Invalid cron expression for task {task_id}")
                return None
            
            # Remove existing job if any (inline to avoid deadlock)
            if task_id in self.jobs:
                old_job_id = self.jobs[task_id]
                try:
                    self.scheduler.remove_job(old_job_id)
                except Exception:
                    pass
                del self.jobs[task_id]
                print(f"Removed existing job {task_id}")
            
            try:
                job = self.scheduler.add_job(
                    func,
                    CronTrigger.from_crontab(cleaned),
                    args=args,
                    kwargs=kwargs,
                    id=f"task_{task_id}",
                    replace_existing=True
                )
                
                self.jobs[task_id] = job.id
                next_run = job.next_run_time
                print(f"Added job {task_id} with cron '{cleaned}', next run: {next_run}")
                return job.id
                
            except Exception as e:
                print(f"Failed to add job {task_id}: {e}")
                return None
    
    def remove_job(self, task_id: str) -> bool:
        """
        Remove a scheduled job.
        
        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if task_id not in self.jobs:
                return False
            
            job_id = self.jobs[task_id]
            try:
                self.scheduler.remove_job(job_id)
            except Exception:
                pass  # Job might already be removed
            
            del self.jobs[task_id]
            print(f"Removed job {task_id}")
            return True
    
    def update_job(
        self,
        task_id: str,
        cron_expr: str,
        enabled: bool,
        func: Callable,
        *args,
        **kwargs
    ) -> bool:
        """
        Update a scheduled job.
        
        Args:
            task_id: Task identifier
            cron_expr: New cron expression
            enabled: Whether the job should be active
            func: Function to execute
            *args, **kwargs: Arguments for the function
        
        Returns:
            True if successful
        """
        # Remove existing job first
        self.remove_job(task_id)
        
        # Add new job if enabled
        if enabled and cron_expr:
            return self.add_job(task_id, cron_expr, func, *args, **kwargs) is not None
        
        return True
    
    def get_job_info(self, task_id: str) -> Optional[Dict]:
        """
        Get information about a scheduled job.
        
        Returns:
            {
                "task_id": str,
                "job_id": str,
                "next_run": datetime or None,
                "cron_expr": str
            }
            or None if not found
        """
        with self._lock:
            if task_id not in self.jobs:
                return None
            
            job_id = self.jobs[task_id]
            try:
                job = self.scheduler.get_job(job_id)
                if job:
                    return {
                        "task_id": task_id,
                        "job_id": job_id,
                        "next_run": job.next_run_time,
                        "pending": job.pending
                    }
            except Exception:
                pass
            
            return None
    
    def list_jobs(self) -> list[Dict]:
        """
        List all scheduled jobs.
        
        Returns:
            List of job info dictionaries
        """
        jobs = []
        with self._lock:
            for task_id, job_id in self.jobs.items():
                try:
                    job = self.scheduler.get_job(job_id)
                    if job:
                        jobs.append({
                            "task_id": task_id,
                            "job_id": job_id,
                            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                            "pending": job.pending
                        })
                except Exception:
                    pass
        return jobs
    
    def pause_job(self, task_id: str) -> bool:
        """Pause a job"""
        with self._lock:
            if task_id not in self.jobs:
                return False
            try:
                self.scheduler.pause_job(self.jobs[task_id])
                return True
            except Exception:
                return False
    
    def resume_job(self, task_id: str) -> bool:
        """Resume a paused job"""
        with self._lock:
            if task_id not in self.jobs:
                return False
            try:
                self.scheduler.resume_job(self.jobs[task_id])
                return True
            except Exception:
                return False
    
    def add_geoip_update_job(self):
        """Add daily GeoIP database update job at 3:00 AM"""
        from geoip_service import download_geoip_database, get_geoip_service, check_update_available
        
        async def update_geoip():
            """Auto-update GeoIP database if newer version available"""
            try:
                check_result = check_update_available()
                if check_result.get("update_available"):
                    latest_info = check_result.get("latest_version")
                    download_url = latest_info.get("download_url") if latest_info else None
                    result = download_geoip_database(url=download_url)
                    if result["success"]:
                        get_geoip_service().reload()
                        print(f"GeoIP database auto-updated: {latest_info.get('latest_version', 'unknown')}")
                    else:
                        print(f"GeoIP auto-update failed: {result['message']}")
                else:
                    print("GeoIP database is up to date")
            except Exception as e:
                print(f"GeoIP auto-update error: {e}")
        
        # Schedule at 3:00 AM daily
        self.add_job("geoip_auto_update", "0 3 * * *", update_geoip)
    
    def remove_geoip_update_job(self):
        """Remove GeoIP auto-update job"""
        self.remove_job("geoip_auto_update")


# Common cron presets
CRON_PRESETS = {
    "every_hour": "0 * * * *",
    "every_2_hours": "0 */2 * * *",
    "every_6_hours": "0 */6 * * *",
    "every_12_hours": "0 */12 * * *",
    "daily": "0 0 * * *",
    "daily_6am": "0 6 * * *",
    "daily_midnight": "0 0 * * *",
    "weekly": "0 0 * * 0",
    "monthly": "0 0 1 * *",
}


def get_cron_description(cron_expr: str) -> str:
    """
    Get human-readable description of a cron expression.
    
    Examples:
        "0 */6 * * *" -> "Every 6 hours"
        "0 0 * * *" -> "Daily at midnight"
    """
    cleaned = SchedulerManager.clean_cron_expression(cron_expr)
    
    # Check presets
    for name, preset in CRON_PRESETS.items():
        if cleaned == preset:
            descriptions = {
                "every_hour": "每小时",
                "every_2_hours": "每2小时",
                "every_6_hours": "每6小时",
                "every_12_hours": "每12小时",
                "daily": "每天",
                "daily_6am": "每天早上6点",
                "daily_midnight": "每天午夜",
                "weekly": "每周",
                "monthly": "每月",
            }
            return descriptions.get(name, name)
    
    # Parse and describe
    parts = cleaned.split(' ')
    if len(parts) != 5:
        return cron_expr
    
    minute, hour, day, month, weekday = parts
    
    # Simple patterns
    if minute == "0" and hour.startswith("*/"):
        interval = hour[2:]
        return f"每{interval}小时"
    
    if minute.startswith("*/"):
        interval = minute[2:]
        return f"每{interval}分钟"
    
    if minute == "0" and hour == "0" and day == "*" and month == "*" and weekday == "*":
        return "每天午夜"
    
    return cron_expr


# Global instance
_scheduler_manager: Optional[SchedulerManager] = None


def get_scheduler() -> SchedulerManager:
    """Get or create global scheduler instance"""
    global _scheduler_manager
    if _scheduler_manager is None:
        _scheduler_manager = SchedulerManager()
    return _scheduler_manager


def init_scheduler() -> SchedulerManager:
    """Initialize and start the global scheduler"""
    scheduler = get_scheduler()
    scheduler.start()
    return scheduler
