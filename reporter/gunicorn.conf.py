"""
Gunicorn settings for the reporter container.

Prometheus metrics need a shared directory when gunicorn runs several worker
processes: each worker writes its samples there and /metrics aggregates them.
The variable has to be set here, in the master, before any worker imports
prometheus_client.
"""

import os
import shutil

bind = "0.0.0.0:" + os.environ.get("PORT", "8000")
workers = int(os.environ.get("GUNICORN_WORKERS", "4"))
threads = int(os.environ.get("GUNICORN_THREADS", "2"))
accesslog = "-"

_metrics_dir = os.environ.setdefault(
    "PROMETHEUS_MULTIPROC_DIR", "/tmp/prometheus_multiproc"
)


def on_starting(server):
    # Stale files from a previous run would be double counted.
    shutil.rmtree(_metrics_dir, ignore_errors=True)
    os.makedirs(_metrics_dir, exist_ok=True)


def child_exit(server, worker):
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(worker.pid)


def worker_exit(server, worker):
    # Let queued Slack alerts finish before the worker goes away.
    import notifier

    notifier.drain(timeout=25)
