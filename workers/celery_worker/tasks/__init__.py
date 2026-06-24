"""Celery task definitions.

Each module contains task functions for specific AI analysis pipelines.
Tasks are auto-discovered by Celery via the task_routes configuration.
"""

from workers.celery_worker.celery_app import celery_app

__all__ = ["celery_app"]
