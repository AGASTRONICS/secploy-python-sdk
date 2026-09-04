import queue
import unittest

from secploy.events import EventHandler
from secploy.sampling import actor_key, bucket, never_sampled, should_send


def event(**context):
    return {"context": context}


class ProtectedTypeTests(unittest.TestCase):
    def test_errors_are_never_sampled(self):
        # A general error tracker samples errors because volume is its problem.
        # This product's value is the rare event, and dropping nine errors in
        # ten would be dropping the thing it exists to find.
        for event_type in ("error", "critical", "fatal", "warning", "warn", "exception"):
            with self.subTest(event_type=event_type):
                self.assertTrue(should_send(event_type, event(identity_key="u1"), 0.01))

    def test_security_signals_are_never_sampled(self):
        signals = (
            "auth.anomaly.detected", "account.takeover.suspected",
            "security.threat.detected", "access.privilege_escalation.detected",
            "data.exfiltration.suspected", "secret.exposed", "incident.opened",
            "fraud.rule.matched", "payment.declined", "compliance.violation",
            "api.abuse.detected", "dependency_scan.completed",
        )
        for signal in signals:
            with self.subTest(signal=signal):
                self.assertTrue(should_send(signal, event(identity_key="u1"), 0.001))

    def test_a_stacktrace_is_always_sent(self):
        # Unambiguous evidence that something threw, whatever it was labelled.
        self.assertTrue(should_send("info", event(stacktrace=["File ..."]), 0.001))

    def test_volume_traffic_is_eligible(self):
        # Without this, sampling does nothing at all.
        for event_type in ("log", "info", "debug", "metric", "http_request", "system_metrics"):
            with self.subTest(event_type=event_type):
                self.assertFalse(never_sampled(event_type))

    def test_case_and_whitespace_do_not_defeat_the_rule(self):
        self.assertTrue(never_sampled("  ERROR  "))
        self.assertTrue(never_sampled("Auth.Anomaly.Detected"))


class RateTests(unittest.TestCase):
    def test_a_full_rate_sends_everything(self):
        for event_type in ("log", "http_request", "error"):
            self.assertTrue(should_send(event_type, event(identity_key="u1"), 1.0))

    def test_a_rate_of_zero_still_sends_what_matters(self):
        # The difference between "quiet" and "blind".
        self.assertTrue(should_send("error", event(identity_key="u1"), 0))
        self.assertFalse(should_send("log", event(identity_key="u1"), 0))

    def test_the_rate_is_honoured_across_actors(self):
        for rate in (0.1, 0.25, 0.5, 0.9):
            kept = sum(
                1 for i in range(20000)
                if should_send("http_request", event(identity_key=f"user-{i}"), rate)
            )
            observed = kept / 20000
            self.assertAlmostEqual(observed, rate, delta=0.02, msg=f"rate {rate}")

    def test_a_nonsense_rate_does_not_lose_events(self):
        for rate in (None, "abc", float("nan")):
            with self.subTest(rate=rate):
                self.assertTrue(should_send("log", event(identity_key="u1"), rate))


class ActorConsistencyTests(unittest.TestCase):
    """The decision that makes sampling compatible with detection."""

    def test_the_same_actor_is_decided_the_same_way_every_time(self):
        # Several detectors read a sequence. A uniform one-in-ten sample leaves
        # every sequence with holes, so a scan of two hundred ids arrives as
        # twenty scattered requests and nothing fires.
        first = should_send("http_request", event(identity_key="user-42"), 0.5)
        for _ in range(500):
            self.assertEqual(
                should_send("http_request", event(identity_key="user-42"), 0.5),
                first,
            )

    def test_a_sampled_in_actor_keeps_its_whole_sequence(self):
        observed = {}
        for actor in range(200):
            key = f"user-{actor}"
            for _ in range(50):
                if should_send("http_request", event(identity_key=key), 0.3):
                    observed[key] = observed.get(key, 0) + 1

        self.assertTrue(observed, "no actor survived sampling")
        for key, count in observed.items():
            self.assertEqual(count, 50, f"{key} was seen {count} of 50; its sequence has holes")

    def test_different_actors_get_different_decisions(self):
        decisions = {
            should_send("http_request", event(identity_key=f"user-{i}"), 0.5)
            for i in range(1000)
        }
        self.assertEqual(decisions, {True, False})


class ActorKeyTests(unittest.TestCase):
    def test_the_most_specific_identifier_wins(self):
        self.assertEqual(
            actor_key(event(identity_key="u1", user_id="u1", session_id="s", ip_address="1.2.3.4")),
            "identity_key:u1",
        )
        self.assertEqual(actor_key(event(session_id="s", ip_address="1.2.3.4")), "session_id:s")
        self.assertEqual(actor_key(event(ip_address="1.2.3.4")), "ip_address:1.2.3.4")

    def test_placeholders_do_not_count_as_actors(self):
        # The SDK fills these in when it knows nothing. Treating them as an
        # actor would put every anonymous request in one bucket.
        self.assertEqual(actor_key(event(identity_key="anonymous", ip_address="unknown")), "")

    def test_a_root_level_field_is_found_too(self):
        self.assertEqual(actor_key({"user_id": "u9"}), "user_id:u9")

    def test_nothing_usable_yields_no_actor(self):
        for payload in ({}, None, "not a dict", {"context": "not a dict"}):
            with self.subTest(payload=payload):
                self.assertEqual(actor_key(payload), "")


class BucketTests(unittest.TestCase):
    def test_it_is_stable_and_in_range(self):
        self.assertEqual(bucket("identity_key:user-1"), bucket("identity_key:user-1"))
        for i in range(1000):
            value = bucket(f"identity_key:user-{i}")
            self.assertGreaterEqual(value, 0.0)
            self.assertLess(value, 1.0)

    def test_it_spreads_evenly(self):
        deciles = [0] * 10
        for i in range(10000):
            deciles[int(bucket(f"identity_key:user-{i}") * 10)] += 1
        for decile, count in enumerate(deciles):
            self.assertTrue(800 <= count <= 1200, f"decile {decile} holds {count}")

    def test_it_matches_the_other_implementations(self):
        # Pinned. An actor bucketed differently by different services would be
        # sampled in by one and out by another.
        self.assertAlmostEqual(bucket("identity_key:user-1"), 0.682777636917308, places=12)


class EventBoundaryTests(unittest.TestCase):
    def make(self, rate):
        q = queue.Queue(maxsize=1000)
        return q, EventHandler(q, sampling_rate=rate)

    def test_sampling_actually_applies_now(self):
        # It was validated, defaulted, stored - and never read. Setting 0.1
        # sent everything.
        q, handler = self.make(0.0)
        for i in range(50):
            handler.send_event("log", {"message": f"line {i}", "context": {"identity_key": f"u{i}"}})

        self.assertTrue(q.empty())
        self.assertEqual(handler.sampled_events, 50)

    def test_errors_still_get_through_at_any_rate(self):
        q, handler = self.make(0.0)
        handler.send_event("error", {"message": "boom", "context": {"identity_key": "u1"}})

        self.assertFalse(q.empty())
        self.assertEqual(handler.sampled_events, 0)

    def test_a_full_rate_changes_nothing(self):
        q, handler = self.make(1.0)
        for i in range(20):
            handler.send_event("log", {"message": f"line {i}"})
        self.assertEqual(q.qsize(), 20)

    def test_drops_are_counted_not_silent(self):
        _, handler = self.make(0.5)
        for i in range(200):
            handler.send_event("log", {"message": "x", "context": {"identity_key": f"u{i}"}})
        self.assertGreater(handler.sampled_events, 0)


if __name__ == "__main__":
    unittest.main()
