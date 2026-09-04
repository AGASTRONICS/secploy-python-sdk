"""
Sampling, without breaking detection.

``sampling_rate`` has been in the configuration since the beginning. It is
documented, defaulted, validated on load, and stored on the client - and it was
never read. Setting ``0.1`` sent everything, so a project that had deliberately
turned its volume down was paying for all of it and did not know.

Making it work is easy. Making it safe is the part that needs a decision, and
the answer is not the one a general error tracker would give.

**Some events are never sampled.** A general tracker samples errors because
volume is its problem. This product's value is the rare event: the one failed
login that mattered, the one probe that succeeded. Dropping nine errors in ten
would be dropping the thing it exists to find. So errors, warnings and every
namespaced security signal always go, whatever the rate. What gets thinned is
the high-volume, low-signal traffic that made sampling desirable in the first
place: logs, metrics, ordinary requests.

**What is sampled is sampled per actor, not per event.** Several detectors read
a *sequence* - how many object ids one caller walked, how a parameter's shape
changed, how a response size drifted. A uniform one-in-ten sample leaves every
sequence with holes, so a scan of two hundred ids arrives as twenty scattered
requests and no detector fires. Bucketing on the actor instead means a caller is
either fully observed or not observed at all: the same fraction of traffic is
kept, but what is kept is coherent enough to still detect something.

The bucketing must stay byte-identical to ``services/sampling.go`` in the ingest
and ``src/sampling.ts`` in the Node SDK. An actor bucketed differently by
different services would be sampled in by one and out by another, which is the
incoherence this design exists to avoid.
"""

import hashlib
from typing import Any, Dict, Optional

# Event types that carry the signal this product exists for.
ALWAYS_SENT_TYPES = frozenset({
    "error", "critical", "fatal", "warning", "warn", "exception",
})

# Namespaced security signals the SDK emits. These are deliberate - an
# application calling out that something happened - and never volume traffic.
ALWAYS_SENT_PREFIXES = (
    "auth.", "account.", "security.", "access.", "data.", "secret.",
    "incident.", "fraud.", "compliance.", "payment.", "api.abuse",
    "dependency_scan.",
)

# Fields that identify who an event is about, most specific first, so sampling
# follows a person where it can and a machine otherwise.
ACTOR_FIELDS = ("identity_key", "user_id", "session_id", "ip_address", "remote_addr")

# What the SDK fills in when it knows nothing. Treating these as an actor would
# put every anonymous request in one bucket, so they would all be sampled in or
# all out together.
_PLACEHOLDERS = frozenset({"anonymous", "unknown", "none", ""})


def never_sampled(event_type: Any, has_stacktrace: bool = False) -> bool:
    """Whether an event must be sent whatever the rate."""
    # A stacktrace is unambiguous evidence that something threw, whatever the
    # event was labelled.
    if has_stacktrace:
        return True

    normalized = str(event_type or "").strip().lower()
    if normalized in ALWAYS_SENT_TYPES:
        return True
    return any(normalized.startswith(prefix) for prefix in ALWAYS_SENT_PREFIXES)


def bucket(value: str) -> float:
    """
    Map a string onto ``[0, 1)`` deterministically.

    The first four bytes of a SHA-256 read as a big-endian unsigned 32-bit
    integer, divided by the full range. Chosen because it is expressible
    identically in Python, Go and JavaScript - all three handle a uint32 without
    loss - so every service buckets an actor the same way.
    """
    digest = hashlib.sha256(str(value).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") / 2 ** 32


def actor_key(payload: Optional[Dict[str, Any]]) -> str:
    """The most specific identifier available for whoever this event is about."""
    if not isinstance(payload, dict):
        return ""

    context = payload.get("context")
    sources = [payload]
    if isinstance(context, dict):
        sources.insert(0, context)

    for field in ACTOR_FIELDS:
        for source in sources:
            value = str(source.get(field) or "").strip()
            if value and value.lower() not in _PLACEHOLDERS:
                return f"{field}:{value}"
    return ""


def _has_stacktrace(payload: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(payload, dict):
        return False
    for source in (payload.get("context"), payload):
        if isinstance(source, dict) and source.get("stacktrace"):
            return True
    return False


def should_send(event_type: Any, payload: Optional[Dict[str, Any]], rate: float) -> bool:
    """
    Whether one event survives sampling.

    Never raises: this sits on the path every event takes, and a sampler that
    failed on an unusual payload would stop the application reporting at all.
    """
    try:
        rate = float(rate)
    except (TypeError, ValueError):
        return True

    # NaN compares false against everything, so an unguarded NaN would fall
    # through every branch below and drop the event. A rate nobody can read is
    # not a reason to stop reporting.
    if rate != rate:
        return True

    if rate >= 1.0:
        return True

    protected = never_sampled(event_type, _has_stacktrace(payload))

    if rate <= 0:
        # A rate of zero still sends what must never be dropped, which is the
        # difference between "quiet" and "blind".
        return protected
    if protected:
        return True

    try:
        key = actor_key(payload)
    except Exception:
        key = ""

    return bucket(key or str(event_type)) < rate
