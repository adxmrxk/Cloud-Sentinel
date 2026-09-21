"""
Slack alert delivery, off the request path.

/ingest used to call the Slack webhook inline, once: a slow webhook added its
full latency to every vulnerable ingest (2 s webhook -> 2 s p95), and one
failed attempt lost the alert for good (1-in-3 failing webhook -> 67%
delivered). Delivery now runs on a small background pool with retries and
exponential backoff, and the audit record's slackNotified flag is updated
when it finishes.

In Lambda there is no background: the execution environment is frozen as
soon as the response is returned, so delivery stays synchronous there (still
with retries). SLACK_DELIVERY=sync|async overrides the choice.
"""

import logging
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

MAX_ATTEMPTS = int(os.environ.get("SLACK_MAX_ATTEMPTS", "4"))
BASE_DELAY_SECONDS = float(os.environ.get("SLACK_RETRY_BASE_SECONDS", "1"))

_executor = None
_executor_lock = threading.Lock()
_pending = set()
_pending_lock = threading.Lock()


def is_async():
    mode = (os.environ.get("SLACK_DELIVERY") or "").strip().lower()
    if mode in ("sync", "async"):
        return mode == "async"
    return not os.environ.get("AWS_LAMBDA_FUNCTION_NAME")


def _get_executor():
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=int(os.environ.get("SLACK_WORKERS", "4")),
                thread_name_prefix="slack",
            )
        return _executor


def deliver_with_retries(send_once, sleep=time.sleep):
    """Call send_once() until it returns True or attempts run out."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if send_once():
            return True
        if attempt < MAX_ATTEMPTS:
            delay = BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            sleep(delay * (0.5 + random.random() / 2))
    return False


def submit(send_once, on_done):
    """Deliver in the background; on_done(delivered) runs when it finishes."""

    def run():
        delivered = False
        try:
            delivered = deliver_with_retries(send_once)
        except Exception:  # never let a worker die silently
            log.exception("Slack delivery crashed")
        try:
            on_done(delivered)
        except Exception:
            log.exception("Recording the Slack delivery result failed")

    future = _get_executor().submit(run)
    with _pending_lock:
        _pending.add(future)
    future.add_done_callback(lambda f: _discard(f))
    return future


def _discard(future):
    with _pending_lock:
        _pending.discard(future)


def drain(timeout=None):
    """Wait for queued deliveries (tests, benchmarks and worker shutdown)."""
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        with _pending_lock:
            pending = list(_pending)
        if not pending:
            return True
        for future in pending:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            try:
                future.result(timeout=remaining)
            except Exception:
                pass
