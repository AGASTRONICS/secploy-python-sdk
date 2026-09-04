"""
Turning an exception into a reportable event.

The SDK already caught crashes through ``sys.excepthook`` and friends, but it
sent them as a wall of formatted text: ``traceback.format_exception`` output, a
list of strings. That works, and the ingest still parses it, but it throws away
information Python is handing us for free.

The traceback object knows which frames these are, what the function was called,
and - crucially - which of them belong to the application rather than to the
standard library or an installed package. Reconstructing that on the server
means guessing from path substrings. Reading it here means knowing.

The formatted strings still go on the wire alongside the frames, so an ingest
that predates this change is unaffected.
"""

import os
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple

# Path fragments that mean "not the application's own code".
#
# Frames inside these move when a dependency is upgraded, which is why grouping
# must not depend on them: a version bump would otherwise re-group every issue
# in the project.
_VENDOR_MARKERS = (
    "site-packages",
    "dist-packages",
    os.sep + "lib" + os.sep + "python",
    os.sep + "venv" + os.sep,
    os.sep + ".venv" + os.sep,
    "<frozen importlib",
)

# Frames beyond this are dropped. A deep framework stack repeats the same outer
# frames on every occurrence and the payload is charged for all of them; the
# innermost frames are what identify the bug.
MAX_FRAMES = 50


def _app_root() -> str:
    try:
        return os.getcwd()
    except Exception:
        return ""


def _is_vendor(filename: str) -> bool:
    lowered = filename.lower()
    return any(marker in lowered for marker in _VENDOR_MARKERS)


def _module_for(filename: str, root: str) -> str:
    """
    Reduce a path to something stable across machines.

    An absolute path differs between a laptop, CI and a container and says
    nothing about the bug. Inside the application root the relative path is
    exactly right; outside it, the last two segments identify the module.
    """
    if not filename:
        return ""
    if filename.startswith("<") and filename.endswith(">"):
        return filename

    if root:
        try:
            relative = os.path.relpath(filename, root)
            if not relative.startswith(".."):
                return relative.replace(os.sep, "/")
        except (ValueError, OSError):
            # Different drive on Windows, or an unusable path.
            pass

    parts = [part for part in filename.replace("\\", "/").split("/") if part]
    return "/".join(parts[-2:]) if parts else filename


def extract_frames(exc_tb, root: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Structured frames from a traceback object, innermost last.

    ``in_app`` is decided here because this is the only place that can decide it
    accurately: the SDK is running inside the application and can see where its
    own code lives.
    """
    if exc_tb is None:
        return []

    if root is None:
        root = _app_root()

    frames: List[Dict[str, Any]] = []
    try:
        summaries = traceback.extract_tb(exc_tb)
    except Exception:
        # A broken traceback is not a reason to lose the exception.
        return []

    for summary in summaries:
        filename = summary.filename or ""
        frames.append({
            "filename": filename,
            "module": _module_for(filename, root),
            "function": summary.name or "",
            "lineno": summary.lineno,
            # The source line as it was, which is what makes an issue page
            # readable without opening an editor. Python gives us this for free
            # when the file is still on disk.
            "context_line": (summary.line or "").strip() or None,
            "in_app": bool(filename) and not _is_vendor(filename),
        })

    return frames[-MAX_FRAMES:] if len(frames) > MAX_FRAMES else frames


def culprit_from(frames: List[Dict[str, Any]]) -> str:
    """
    Where the bug is: the innermost application frame.

    "Where did this happen" almost never means the framework internals at the
    bottom of the stack; it means the deepest line of code somebody here wrote.
    """
    chosen = None
    for frame in frames:
        if frame.get("in_app"):
            chosen = frame
    if chosen is None and frames:
        chosen = frames[-1]
    if chosen is None:
        return ""

    module = chosen.get("module") or ""
    function = chosen.get("function") or ""
    return f"{module} in {function}" if function else module


def normalize_exception(error: Any) -> Tuple[type, BaseException, Any]:
    """
    Accept what callers actually pass.

    ``capture_exception()`` with no argument should pick up the exception being
    handled, which is what makes it usable inside an ``except`` block. A string
    or any other value is wrapped rather than refused: losing the report is a
    worse outcome than an imperfect one.
    """
    if error is None:
        exc_type, exc_value, exc_tb = sys.exc_info()
        if exc_value is not None:
            return exc_type, exc_value, exc_tb
        wrapped = RuntimeError("capture_exception() called with no active exception")
        return type(wrapped), wrapped, None

    if isinstance(error, BaseException):
        return type(error), error, error.__traceback__

    wrapped = RuntimeError(f"Non-exception reported: {error!r}"[:1000])
    return type(wrapped), wrapped, None


def parse_exception(error: Any = None, root: Optional[str] = None) -> Dict[str, Any]:
    """
    Everything worth reporting about one exception.

    Returns both shapes: the structured frames, and the formatted strings the
    ingest has always accepted.
    """
    exc_type, exc_value, exc_tb = normalize_exception(error)

    try:
        stacktrace = traceback.format_exception(exc_type, exc_value, exc_tb)
    except Exception:
        stacktrace = [f"{getattr(exc_type, '__name__', 'Error')}: {exc_value}"]

    frames = extract_frames(exc_tb, root)

    return {
        "type": getattr(exc_type, "__name__", "Error"),
        "value": str(exc_value),
        "frames": frames,
        "stacktrace": stacktrace,
        "culprit": culprit_from(frames),
    }
