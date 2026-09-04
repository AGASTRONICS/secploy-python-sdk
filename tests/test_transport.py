import queue
import random
import time
import unittest
from unittest.mock import Mock, patch

from secploy.events import DEFAULT_MAX_QUEUE_SIZE, EventHandler
from secploy.processor import EventProcessor
from secploy.transport import (
    DELIVERED,
    DROP,
    MAX_BACKOFF_SECONDS,
    MAX_RETRY_AFTER_SECONDS,
    RETRY,
    backoff_delay,
    classify_status,
    parse_retry_after,
)


class ClassifyStatusTests(unittest.TestCase):
    def test_every_2xx_is_delivered(self):
        for code in (200, 201, 202, 204, 299):
            self.assertEqual(classify_status(code), DELIVERED, code)

    def test_a_sampled_response_is_not_a_failure(self):
        # The ingest answers 202 {"status": "sampled"} when server-side sampling
        # drops a batch. Reading that as a failure made the client resend it
        # five times, so sampling multiplied load instead of reducing it.
        self.assertEqual(classify_status(202), DELIVERED)

    def test_client_errors_are_permanent(self):
        for code in (400, 401, 403, 404, 413, 422):
            self.assertEqual(classify_status(code), DROP, code)

    def test_some_client_errors_are_worth_retrying(self):
        for code in (408, 425, 429):
            self.assertEqual(classify_status(code), RETRY, code)

    def test_server_errors_are_retried(self):
        for code in (500, 502, 503, 504):
            self.assertEqual(classify_status(code), RETRY, code)

    def test_no_response_is_retried(self):
        self.assertEqual(classify_status(None), RETRY)

    def test_an_unreadable_status_is_not_taken_as_success(self):
        self.assertEqual(classify_status("nonsense"), RETRY)


class RetryAfterTests(unittest.TestCase):
    def test_seconds_are_read(self):
        self.assertEqual(parse_retry_after("30"), 30.0)
        self.assertEqual(parse_retry_after(" 5 "), 5.0)

    def test_absent_or_unreadable_values_fall_back_to_our_own_backoff(self):
        for value in (None, "", "Wed, 21 Oct 2026 07:28:00 GMT", "soon", "-1"):
            self.assertIsNone(parse_retry_after(value))

    def test_an_absurd_delay_is_capped(self):
        self.assertEqual(parse_retry_after("999999"), MAX_RETRY_AFTER_SECONDS)


class BackoffTests(unittest.TestCase):
    def test_the_delay_grows(self):
        rng = random.Random(1)
        # Full jitter makes any single draw noisy, so compare the ceilings via
        # the maximum across many draws.
        early = max(backoff_delay(0, rng=rng) for _ in range(200))
        late = max(backoff_delay(4, rng=rng) for _ in range(200))
        self.assertGreater(late, early)

    def test_the_delay_is_capped(self):
        rng = random.Random(2)
        for attempt in range(0, 40):
            self.assertLessEqual(backoff_delay(attempt, rng=rng), MAX_BACKOFF_SECONDS)

    def test_the_delay_is_jittered(self):
        # A fleet that failed together must not return together. Identical
        # delays across clients is exactly the thundering herd this avoids.
        rng = random.Random(3)
        delays = {backoff_delay(3, rng=rng) for _ in range(50)}
        self.assertGreater(len(delays), 1)

    def test_retry_after_wins(self):
        self.assertEqual(backoff_delay(0, retry_after=12.0), 12.0)

    def test_an_absurd_retry_after_is_still_capped(self):
        self.assertEqual(backoff_delay(0, retry_after=1e9), MAX_RETRY_AFTER_SECONDS)


def response(status_code, text="", headers=None):
    resp = Mock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


class ProcessorDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.queue = queue.Queue(maxsize=100)
        self.processor = EventProcessor(
            queue=self.queue,
            ingest_url="https://ingest.example.com/ingest",
            headers_callback=lambda: {},
            batch_size=10,
            flush_interval=60,
            max_retry=3,
        )
        # No real sleeping in tests.
        patcher = patch("secploy.processor.backoff_delay", return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_delivered_batch_is_sent_once(self):
        with patch.object(self.processor._session, "post", return_value=response(200)) as post:
            self.assertTrue(self.processor._send_batch([{"a": 1}]))
        self.assertEqual(post.call_count, 1)
        self.assertEqual(self.processor.dropped_events, 0)

    def test_a_sampled_batch_is_not_resent(self):
        with patch.object(self.processor._session, "post",
                          return_value=response(202, '{"status":"sampled"}')) as post:
            self.processor._send_batch([{"a": 1}])
        self.assertEqual(post.call_count, 1)

    def test_a_rejected_batch_is_dropped_not_retried(self):
        # The poison pill. One malformed event used to be retried against every
        # subsequent flush, forever, taking the queue behind it down too.
        with patch.object(self.processor._session, "post",
                          return_value=response(400, "invalid payload")) as post:
            cleared = self.processor._send_batch([{"a": 1}, {"b": 2}])

        self.assertTrue(cleared, "a rejected batch must be cleared, not kept")
        self.assertEqual(post.call_count, 1, "a 400 is permanent; retrying cannot help")
        self.assertEqual(self.processor.dropped_events, 2)

    def test_a_server_error_is_retried_then_given_up_on(self):
        with patch.object(self.processor._session, "post", return_value=response(503)) as post:
            cleared = self.processor._send_batch([{"a": 1}])

        self.assertEqual(post.call_count, 3)
        self.assertTrue(cleared, "the batch is released rather than held forever")
        self.assertEqual(self.processor.dropped_events, 1)

    def test_a_transient_failure_that_recovers_is_delivered(self):
        with patch.object(self.processor._session, "post",
                          side_effect=[response(503), response(200)]) as post:
            self.processor._send_batch([{"a": 1}])

        self.assertEqual(post.call_count, 2)
        self.assertEqual(self.processor.dropped_events, 0)

    def test_a_connection_error_is_retried(self):
        with patch.object(self.processor._session, "post",
                          side_effect=[OSError("no route to host"), response(200)]) as post:
            self.processor._send_batch([{"a": 1}])
        self.assertEqual(post.call_count, 2)

    def test_a_retry_after_header_is_honoured(self):
        with patch("secploy.processor.backoff_delay") as delay:
            delay.return_value = 0
            with patch.object(self.processor._session, "post",
                              side_effect=[response(429, headers={"Retry-After": "7"}),
                                           response(200)]):
                self.processor._send_batch([{"a": 1}])

        self.assertEqual(delay.call_args.args[0], 0)
        self.assertEqual(delay.call_args.args[1], 7.0)

    def test_delivery_never_raises(self):
        # This runs on a daemon thread; an escaping exception would end event
        # delivery for the life of the process.
        with patch.object(self.processor._session, "post", side_effect=RuntimeError("boom")):
            self.assertTrue(self.processor._send_batch([{"a": 1}]))


class ProcessorFlushTests(unittest.TestCase):
    """Exercises the real background loop rather than a re-implementation."""

    def make_processor(self, queue_obj, **kwargs):
        options = dict(
            ingest_url="https://ingest.example.com/ingest",
            headers_callback=lambda: {},
            batch_size=2,
            flush_interval=60,
            max_retry=1,
        )
        options.update(kwargs)
        return EventProcessor(queue=queue_obj, **options)

    def test_a_full_batch_is_delivered(self):
        q = queue.Queue(maxsize=100)
        processor = self.make_processor(q)

        with patch.object(processor._session, "post", return_value=response(200)) as post:
            processor.start()
            self.addCleanup(processor.stop)
            EventHandler(q).send_event("error", {"message": "one"})
            EventHandler(q).send_event("error", {"message": "two"})
            deadline = time.time() + 5
            while post.call_count == 0 and time.time() < deadline:
                time.sleep(0.02)

        self.assertEqual(post.call_count, 1)
        sent = post.call_args.kwargs["json"]["events"]
        self.assertEqual([e["payload"]["message"] for e in sent], ["one", "two"])

    def test_a_lone_event_is_flushed_on_time_not_left_waiting(self):
        # The Node port of this loop only evaluated the time-based flush while
        # draining the queue, so on a quiet application a single event sat
        # unsent until the next one happened to arrive. This is the regression
        # test for that shape of bug.
        q = queue.Queue(maxsize=100)
        processor = self.make_processor(q, batch_size=100, flush_interval=0)

        with patch.object(processor._session, "post", return_value=response(200)) as post:
            processor.start()
            self.addCleanup(processor.stop)
            EventHandler(q).send_event("error", {"message": "alone"})
            deadline = time.time() + 5
            while post.call_count == 0 and time.time() < deadline:
                time.sleep(0.02)

        self.assertEqual(post.call_count, 1)
        sent = post.call_args.kwargs["json"]["events"]
        self.assertEqual([e["payload"]["message"] for e in sent], ["alone"])

    def test_a_stuck_ingest_does_not_stall_later_events(self):
        # A batch the server rejects is released, so the events behind it still
        # get their turn. Before, the rejected batch was retried in front of
        # them forever.
        q = queue.Queue(maxsize=100)
        processor = self.make_processor(q, batch_size=1)

        responses = [response(400, "invalid payload"), response(200), response(200)]
        with patch.object(processor._session, "post", side_effect=responses) as post:
            processor.start()
            self.addCleanup(processor.stop)
            for message in ("poison", "good-1", "good-2"):
                EventHandler(q).send_event("error", {"message": message})
            deadline = time.time() + 5
            while post.call_count < 3 and time.time() < deadline:
                time.sleep(0.02)

        self.assertEqual(post.call_count, 3)
        delivered = [
            call.kwargs["json"]["events"][0]["payload"]["message"]
            for call in post.call_args_list
        ]
        self.assertEqual(delivered, ["poison", "good-1", "good-2"])
        self.assertEqual(processor.dropped_events, 1)

    def test_shutdown_drains_the_queue_not_just_the_batch(self):
        # Events still sitting in the queue at stop() used to be discarded in
        # silence - exactly the events a process shutting down most needs to
        # report.
        q = queue.Queue(maxsize=100)
        processor = self.make_processor(q, batch_size=1000, flush_interval=3600)

        with patch.object(processor._session, "post", return_value=response(200)) as post:
            processor.start()
            for message in ("a", "b", "c"):
                EventHandler(q).send_event("error", {"message": message})
            time.sleep(0.2)
            processor.stop()

        self.assertGreaterEqual(post.call_count, 1)
        delivered = [
            event["payload"]["message"]
            for call in post.call_args_list
            for event in call.kwargs["json"]["events"]
        ]
        self.assertCountEqual(delivered, ["a", "b", "c"])

    def test_shutdown_does_not_hang_on_a_dead_ingest(self):
        # One attempt, no backoff. An application calling close() would rather
        # lose a batch than wait out a retry schedule.
        q = queue.Queue(maxsize=100)
        processor = self.make_processor(q, batch_size=1000, flush_interval=3600, max_retry=5)

        with patch.object(processor._session, "post", return_value=response(503)) as post:
            processor.start()
            EventHandler(q).send_event("error", {"message": "a"})
            time.sleep(0.2)
            started = time.time()
            processor.stop()
            elapsed = time.time() - started

        self.assertLess(elapsed, 5.0)
        self.assertLessEqual(post.call_count, 2)


class BoundedQueueTests(unittest.TestCase):
    def test_the_default_bound_matches_the_documented_config_default(self):
        from secploy.lib.config import DEFAULT_CONFIG
        self.assertEqual(DEFAULT_MAX_QUEUE_SIZE, DEFAULT_CONFIG["max_queue_size"])

    def test_the_queue_does_not_grow_without_bound(self):
        # The failure this prevents: an unreachable ingest growing the host
        # application's memory until the application dies.
        q = queue.Queue(maxsize=5)
        handler = EventHandler(q)

        for i in range(1000):
            handler.send_event("error", {"message": f"event-{i}"})

        self.assertEqual(q.qsize(), 5)
        self.assertEqual(handler.dropped_events, 995)

    def test_the_newest_events_are_the_ones_kept(self):
        # For a security agent, what is happening now matters more than what
        # happened at the start of an outage.
        q = queue.Queue(maxsize=3)
        handler = EventHandler(q)

        for i in range(10):
            handler.send_event("error", {"message": f"event-{i}"})

        kept = [q.get_nowait()["payload"]["message"] for _ in range(3)]
        self.assertEqual(kept, ["event-7", "event-8", "event-9"])

    def test_enqueueing_never_blocks_the_caller(self):
        # send_event runs on the application's own request path.
        q = queue.Queue(maxsize=1)
        handler = EventHandler(q)

        for _ in range(50):
            handler.send_event("error", {"message": "x"})

        self.assertEqual(q.qsize(), 1)

    def test_a_drop_is_counted_not_silent(self):
        q = queue.Queue(maxsize=1)
        handler = EventHandler(q)

        handler.send_event("error", {"message": "a"})
        self.assertEqual(handler.dropped_events, 0)

        handler.send_event("error", {"message": "b"})
        self.assertEqual(handler.dropped_events, 1)


if __name__ == "__main__":
    unittest.main()
