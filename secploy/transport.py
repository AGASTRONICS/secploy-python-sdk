"""
Delivery policy for the event transport.

Three rules decide everything this module exists for, and each of them was a
real failure before it was written down.

**Any 2xx means delivered.** The previous transport accepted only ``200``. The
ingest answers ``202 {"status": "sampled"}`` when a project's server-side
sampling rate drops a batch - so every sampled batch was read as a failure and
resent five times. Server-side sampling, whose entire purpose is to reduce load,
multiplied it instead.

**A 4xx is permanent, so the batch is dropped.** The previous transport cleared
its buffer only on success. One malformed event that earns a ``400`` therefore
stayed in the buffer forever, was retried against every subsequent flush, and
took the rest of the queue down with it while memory grew without bound. A
request the server has rejected on its content will be rejected identically
next time; the only useful response is to drop it and say so.

**Everything else backs off.** Network errors, 5xx, 429 and 408 are worth
retrying, but not immediately and not in lockstep. The old fixed one-second
sleep meant every client in a fleet retried in the same rhythm, so an ingest
recovering from an outage was hit by the entire fleet at once, in phase.
"""

import random
from typing import Optional

# Delivery outcomes.
DELIVERED = "delivered"
RETRY = "retry"
DROP = "drop"

# Backoff bounds. The cap matters more than the base: it is what stops a long
# outage from turning into an ever-lengthening silence.
INITIAL_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0

# A server asking us to wait longer than this is either broken or telling us to
# go away for the rest of the day; either way we resume on our own schedule.
MAX_RETRY_AFTER_SECONDS = 300.0

# Status codes that are worth trying again even though they are 4xx.
RETRYABLE_CLIENT_ERRORS = frozenset({
    408,  # request timeout
    425,  # too early
    429,  # rate limited - the server will usually tell us how long to wait
})


def classify_status(status_code: Optional[int]) -> str:
    """
    Decide what a response status means for the batch that produced it.

    ``None`` stands for "no response at all" - a connection error, a timeout, a
    DNS failure - which is always worth retrying.
    """
    if status_code is None:
        return RETRY

    try:
        code = int(status_code)
    except (TypeError, ValueError):
        # An unreadable status is not evidence of delivery.
        return RETRY

    if 200 <= code < 300:
        return DELIVERED

    if code in RETRYABLE_CLIENT_ERRORS:
        return RETRY

    if 400 <= code < 500:
        # The server has judged the content. Sending it again produces the same
        # judgement, so the batch is dropped rather than retried forever.
        return DROP

    if code >= 500:
        return RETRY

    # 1xx and 3xx are not answers to a POST we can act on. Treat as transient
    # rather than discarding data on an ambiguity.
    return RETRY


def parse_retry_after(value) -> Optional[float]:
    """
    Read a ``Retry-After`` header, in seconds.

    Only the delta-seconds form is honoured. The HTTP-date form is legal but
    rare from an API, and misreading a date as a duration is a worse failure
    than ignoring it and using our own backoff.
    """
    if value is None:
        return None

    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        return None

    if seconds < 0:
        return None

    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def backoff_delay(attempt: int, retry_after: Optional[float] = None,
                  rng: Optional[random.Random] = None) -> float:
    """
    How long to wait before retry number ``attempt`` (0-based).

    An explicit ``Retry-After`` wins, because the server knows more than we do
    about when it will be ready. Otherwise: exponential growth with full
    jitter - the delay is drawn uniformly from ``[0, ceiling]`` rather than
    sitting at the ceiling, so a fleet of clients that failed together does not
    return together.
    """
    if retry_after is not None and retry_after >= 0:
        return min(retry_after, MAX_RETRY_AFTER_SECONDS)

    exponent = max(0, int(attempt))
    # Cap the exponent before shifting so a long-lived retry loop cannot
    # overflow into an enormous float.
    ceiling = min(INITIAL_BACKOFF_SECONDS * (2 ** min(exponent, 10)), MAX_BACKOFF_SECONDS)

    generator = rng or random
    return generator.uniform(0, ceiling)
