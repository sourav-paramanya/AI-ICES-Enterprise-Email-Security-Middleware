"""AI-ICES Celery Worker Application.

Central Celery application for asynchronous task processing.
Routes tasks to appropriate queues for NLP, Vision, URL, CDR analysis,
threat scoring, and remediation workflows.
"""

import logging
from functools import lru_cache

from celery import Celery

from shared.config.settings import get_settings
from shared.logging.logger import setup_logging

logger = logging.getLogger(__name__)


@lru_cache
def get_celery_app() -> Celery:
    settings = get_settings()

    app = Celery(
        "ai_ices",
        broker=settings.CELERY_BROKER,
        backend=settings.CELERY_RESULT_BACKEND,
    )

    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=300,
        task_soft_time_limit=240,
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=100,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_queue="default",
        task_default_exchange="default",
        task_default_routing_key="default",
        task_routes={
            "workers.celery_worker.tasks.nlp.*": {"queue": "nlp_analysis"},
            "workers.celery_worker.tasks.vision.*": {"queue": "vision_analysis"},
            "workers.celery_worker.tasks.url.*": {"queue": "url_analysis"},
            "workers.celery_worker.tasks.cdr.*": {"queue": "cdr_analysis"},
            "workers.celery_worker.tasks.scoring.*": {"queue": "threat_scoring"},
            "workers.celery_worker.tasks.remediation.*": {"queue": "remediation"},
        },
        task_queues=(
            {
                "name": "default",
                "exchange": "default",
                "routing_key": "default",
            },
            {
                "name": "nlp_analysis",
                "exchange": "security.analysis",
                "routing_key": "nlp",
            },
            {
                "name": "vision_analysis",
                "exchange": "security.analysis",
                "routing_key": "vision",
            },
            {
                "name": "url_analysis",
                "exchange": "security.analysis",
                "routing_key": "url",
            },
            {
                "name": "cdr_analysis",
                "exchange": "security.analysis",
                "routing_key": "cdr",
            },
            {
                "name": "threat_scoring",
                "exchange": "security.analysis",
                "routing_key": "scoring",
            },
            {
                "name": "remediation",
                "exchange": "remediation",
                "routing_key": "remediation",
            },
        ),
    )

    return app


celery_app = get_celery_app()


def start_worker() -> None:
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
    logger.info(
        "Starting Celery worker with concurrency=%s",
        settings.CELERY_WORKER_CONCURRENCY,
    )
    celery_app.worker_main(
        argv=[
            "worker",
            "--loglevel=info",
            f"--concurrency={settings.CELERY_WORKER_CONCURRENCY}",
            "--hostname=ai-ices-worker@%h",
        ]
    )
