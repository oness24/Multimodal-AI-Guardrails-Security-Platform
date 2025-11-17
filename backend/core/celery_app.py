"""
Celery application for asynchronous task processing.

This module configures Celery for handling long-running tasks such as:
- Attack generation (Red Team)
- Vulnerability scanning
- Threat modeling
- ML model inference
- Report generation
- Data processing
"""
from datetime import datetime, timedelta, timezone

from celery import Celery
from celery.result import AsyncResult
from celery.schedules import crontab

from backend.core.config import settings

# Create Celery application
celery_app = Celery(
    "adversarial_shield",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        # Auto-discover tasks from these modules
        "backend.redteam.tasks",
        "backend.guardrails.tasks",
        "backend.scanner.tasks",
        "backend.threat_intel.tasks",
        "backend.alerting.tasks",
    ],
)

# Celery Configuration
celery_app.conf.update(
    # Task Settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Task execution settings
    task_track_started=True,
    task_time_limit=settings.attack_timeout_seconds,  # Hard time limit (5 minutes)
    task_soft_time_limit=settings.attack_timeout_seconds - 30,  # Soft limit (4m 30s)
    task_acks_late=True,  # Acknowledge task after execution
    task_reject_on_worker_lost=True,  # Reject task if worker dies
    # Result backend settings
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={
        "master_name": "mymaster",
        "visibility_timeout": 3600,
    },
    # Connection settings
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    # Worker settings
    worker_prefetch_multiplier=4,  # Prefetch 4 tasks per worker
    worker_max_tasks_per_child=1000,  # Restart worker after 1000 tasks (prevent memory leaks)
    worker_disable_rate_limits=False,
    # Task routing
    task_routes={
        "backend.redteam.tasks.*": {"queue": "redteam", "priority": 5},
        "backend.guardrails.tasks.*": {"queue": "guardrails", "priority": 9},  # High priority
        "backend.scanner.tasks.*": {"queue": "scanner", "priority": 3},
        "backend.threat_intel.tasks.*": {"queue": "threat_intel", "priority": 2},
        "backend.alerting.tasks.*": {"queue": "alerting", "priority": 10},  # Highest priority
    },
    # Task priority settings
    task_default_priority=5,
    task_inherit_parent_priority=True,
    # Beat (periodic tasks) settings
    beat_schedule={
        # Cleanup expired results every hour
        "cleanup-expired-results": {
            "task": "backend.core.celery_app.cleanup_expired_results",
            "schedule": crontab(minute=0),  # Every hour
        },
        # Update threat intelligence every 6 hours
        "update-threat-intelligence": {
            "task": "backend.threat_intel.tasks.update_threat_database",
            "schedule": crontab(minute=0, hour="*/6"),  # Every 6 hours
        },
        # Generate security reports daily
        "generate-daily-reports": {
            "task": "backend.alerting.tasks.generate_daily_security_report",
            "schedule": crontab(minute=0, hour=8),  # 8 AM UTC daily
        },
        # Clean up old attack logs weekly
        "cleanup-old-logs": {
            "task": "backend.core.celery_app.cleanup_old_attack_logs",
            "schedule": crontab(minute=0, hour=3, day_of_week=1),  # Monday 3 AM
        },
    },
    # Error handling
    task_annotations={
        "*": {
            "rate_limit": "100/m",  # Global rate limit: 100 tasks per minute
            "max_retries": 3,
            "default_retry_delay": 60,  # 1 minute retry delay
        },
        "backend.guardrails.tasks.*": {
            "rate_limit": "1000/m",  # Higher rate for guardrails (real-time)
            "max_retries": 1,  # Fewer retries for real-time tasks
        },
        "backend.alerting.tasks.*": {
            "rate_limit": "500/m",
            "max_retries": 5,  # More retries for critical alerts
        },
    },
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)

# Event monitoring (for Flower and other tools)
celery_app.conf.worker_send_task_events = True
celery_app.conf.task_send_sent_event = True


# Periodic maintenance tasks
@celery_app.task(name="backend.core.celery_app.cleanup_expired_results")
def cleanup_expired_results():
    """
    Clean up expired task results from Redis.
    This prevents Redis from growing indefinitely.
    """
    from celery.result import AsyncResult

    # This is handled automatically by result_expires setting
    # But we can add custom logic here if needed
    return {"status": "completed", "message": "Expired results cleaned up"}


@celery_app.task(name="backend.core.celery_app.cleanup_old_attack_logs")
def cleanup_old_attack_logs():
    """
    Clean up attack logs older than 90 days from database.
    Keeps database size manageable while retaining recent data.
    """
    import asyncio
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete

    from backend.core.database import get_db_session
    from backend.core.models import AttackLog, DetectionLog

    async def _cleanup():
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)

        async for db in get_db_session():
            # Delete old attack logs
            attack_result = await db.execute(
                delete(AttackLog).where(AttackLog.created_at < cutoff_date)
            )

            # Delete old detection logs
            detection_result = await db.execute(
                delete(DetectionLog).where(DetectionLog.created_at < cutoff_date)
            )

            await db.commit()

            return {
                "attack_logs_deleted": attack_result.rowcount,
                "detection_logs_deleted": detection_result.rowcount,
            }

    # Run async cleanup in sync context
    result = asyncio.run(_cleanup())
    return result


@celery_app.task(name="backend.core.celery_app.health_check")
def health_check():
    """
    Simple health check task to verify Celery is working.
    Can be called from monitoring systems.
    """
    return {
        "status": "healthy",
        "environment": settings.environment,
        "timestamp": str(datetime.now(timezone.utc)),
    }


# Task error handler
@celery_app.task(bind=True, max_retries=3)
def error_handler(self, uuid):
    """Handle task errors and send alerts."""
    from backend.alerting.tasks import send_task_failure_alert

    # Get task result
    result = AsyncResult(uuid)

    if result.failed():
        # Send alert about failed task
        send_task_failure_alert.delay(
            task_id=uuid,
            task_name=result.name,
            error=str(result.info),
        )


if __name__ == "__main__":
    # For development/testing
    celery_app.start()
