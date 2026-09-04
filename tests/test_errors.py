import os
import unittest

from secploy.errors import (
    MAX_FRAMES,
    culprit_from,
    extract_frames,
    normalize_exception,
    parse_exception,
)


def raise_and_catch(exc=None):
    """Produce a real traceback rather than a synthetic one."""
    try:
        if exc is None:
            raise ValueError("negative amount")
        raise exc
    except BaseException as caught:  # noqa: BLE001 - deliberate
        return caught


def nested():
    def inner():
        raise KeyError("missing")

    def outer():
        inner()

    try:
        outer()
    except KeyError as caught:
        return caught


class NormalizeTests(unittest.TestCase):
    def test_an_exception_passes_through(self):
        error = raise_and_catch()
        exc_type, exc_value, exc_tb = normalize_exception(error)
        self.assertIs(exc_type, ValueError)
        self.assertIs(exc_value, error)
        self.assertIsNotNone(exc_tb)

    def test_no_argument_picks_up_the_active_exception(self):
        # This is the shape it is nearly always used in:
        #     except PaymentError:
        #         client.capture_exception()
        try:
            raise RuntimeError("in flight")
        except RuntimeError:
            exc_type, exc_value, exc_tb = normalize_exception(None)

        self.assertIs(exc_type, RuntimeError)
        self.assertEqual(str(exc_value), "in flight")
        self.assertIsNotNone(exc_tb)

    def test_no_argument_and_no_active_exception_still_reports(self):
        # Losing the report is worse than an imperfect one.
        exc_type, exc_value, _ = normalize_exception(None)
        self.assertIs(exc_type, RuntimeError)
        self.assertIn("no active exception", str(exc_value))

    def test_a_non_exception_is_wrapped_rather_than_refused(self):
        _, exc_value, _ = normalize_exception("just a string")
        self.assertIn("just a string", str(exc_value))


class FrameTests(unittest.TestCase):
    def test_frames_are_extracted_innermost_last(self):
        # The convention shared with the Node SDK and the ingest. Everything
        # downstream reads the last frame as "where the bug is".
        error = nested()
        frames = extract_frames(error.__traceback__)

        self.assertGreaterEqual(len(frames), 3)
        self.assertEqual(frames[-1]["function"], "inner")

    def test_each_frame_names_its_module_and_line(self):
        frames = extract_frames(raise_and_catch().__traceback__)
        frame = frames[-1]

        self.assertTrue(frame["module"])
        self.assertIsInstance(frame["lineno"], int)
        self.assertEqual(frame["function"], "raise_and_catch")

    def test_the_source_line_is_captured(self):
        # What makes an issue page readable without opening an editor.
        frames = extract_frames(raise_and_catch().__traceback__)
        self.assertIn("raise", frames[-1]["context_line"])

    def test_application_frames_are_marked_in_app(self):
        # Decided here because this is the only place that can decide it
        # accurately: the SDK runs inside the application.
        frames = extract_frames(raise_and_catch().__traceback__)
        self.assertTrue(frames[-1]["in_app"])

    def test_site_packages_are_not_in_app(self):
        # A dependency upgrade moves every line inside it, so those frames must
        # not decide an issue's identity.
        frames = extract_frames(raise_and_catch().__traceback__)
        vendored = dict(frames[-1])
        vendored["filename"] = "/usr/local/lib/python3.11/site-packages/django/db/query.py"

        from secploy.errors import _is_vendor

        self.assertTrue(_is_vendor(vendored["filename"]))
        self.assertFalse(_is_vendor("/app/orders/service.py"))

    def test_module_paths_are_relative_to_the_application(self):
        # An absolute path differs between a laptop, CI and a container.
        from secploy.errors import _module_for

        root = os.sep + "app"
        self.assertEqual(_module_for(os.path.join(root, "orders", "service.py"), root), "orders/service.py")

    def test_a_path_outside_the_root_keeps_its_tail(self):
        from secploy.errors import _module_for

        self.assertEqual(
            _module_for("/usr/local/lib/python3.11/site-packages/django/query.py", "/app"),
            "django/query.py",
        )

    def test_no_traceback_yields_no_frames(self):
        self.assertEqual(extract_frames(None), [])

    def test_a_deep_stack_is_capped_keeping_the_innermost(self):
        # Runaway recursion produces a stack that differs in depth every time;
        # truncating the wrong end would drop the frames that identify the bug.
        def recurse(depth):
            if depth == 0:
                raise RecursionError("deep")
            recurse(depth - 1)

        try:
            recurse(MAX_FRAMES + 40)
        except RecursionError as caught:
            frames = extract_frames(caught.__traceback__)

        self.assertLessEqual(len(frames), MAX_FRAMES)
        self.assertEqual(frames[-1]["function"], "recurse")


class CulpritTests(unittest.TestCase):
    def test_the_innermost_application_frame_is_the_culprit(self):
        # "Where did this happen" means our deepest line, not the framework
        # internals at the bottom of the stack.
        frames = [
            {"module": "api/views.py", "function": "dispatch", "in_app": True},
            {"module": "django/query.py", "function": "get", "in_app": False},
            {"module": "orders/service.py", "function": "load_order", "in_app": True},
            {"module": "django/base.py", "function": "execute", "in_app": False},
        ]
        self.assertEqual(culprit_from(frames), "orders/service.py in load_order")

    def test_it_falls_back_when_nothing_is_in_app(self):
        frames = [{"module": "urllib3/connection.py", "function": "_new_conn", "in_app": False}]
        self.assertEqual(culprit_from(frames), "urllib3/connection.py in _new_conn")

    def test_no_frames_means_no_culprit(self):
        self.assertEqual(culprit_from([]), "")


class ParseTests(unittest.TestCase):
    def test_both_shapes_are_produced(self):
        # Structured frames for grouping and display; the formatted strings so
        # an ingest that predates them still understands the event.
        parsed = parse_exception(raise_and_catch())

        self.assertEqual(parsed["type"], "ValueError")
        self.assertEqual(parsed["value"], "negative amount")
        self.assertTrue(parsed["frames"])
        self.assertTrue(parsed["stacktrace"])
        self.assertIn("ValueError", "".join(parsed["stacktrace"]))

    def test_a_culprit_is_named(self):
        self.assertIn("raise_and_catch", parse_exception(raise_and_catch())["culprit"])

    def test_an_exception_without_a_traceback_still_parses(self):
        # A constructed but never-raised exception has none.
        parsed = parse_exception(ValueError("never raised"))
        self.assertEqual(parsed["type"], "ValueError")
        self.assertEqual(parsed["frames"], [])
        self.assertTrue(parsed["stacktrace"])

    def test_parsing_never_raises(self):
        for value in (None, "string", 42, object(), {"a": 1}):
            with self.subTest(value=value):
                parsed = parse_exception(value)
                self.assertTrue(parsed["type"])
                self.assertTrue(parsed["stacktrace"])


class WireParityTests(unittest.TestCase):
    """The frame shape both SDKs put on the wire has to match."""

    def test_a_frame_carries_the_fields_the_ingest_reads(self):
        # secploy-ingest/services/grouping.go FramesFromContext reads exactly
        # these keys. A rename on either side is a silent regrouping.
        frame = extract_frames(raise_and_catch().__traceback__)[-1]

        for key in ("filename", "module", "function", "in_app"):
            self.assertIn(key, frame, f"the ingest reads {key!r}")

        self.assertIsInstance(frame["in_app"], bool)
        self.assertIsInstance(frame["module"], str)
        self.assertIsInstance(frame["function"], str)


if __name__ == "__main__":
    unittest.main()
