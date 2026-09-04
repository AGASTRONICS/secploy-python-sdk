import queue
import unittest

from secploy.events import EventHandler
from secploy.scrubbing import (
    MAX_ITEMS,
    REDACTED,
    Scrubber,
    hash_session_id,
    normalize_key,
    scrub_string,
)

scrubber = Scrubber()


class DeniedKeyTests(unittest.TestCase):
    def test_credentials_are_redacted_whatever_the_naming_style(self):
        # "API-Key", "api_key" and "apiKey" are one rule, not three.
        for key in ("password", "API_KEY", "apiKey", "Authorization", "x-api-key", "Set-Cookie"):
            with self.subTest(key=key):
                self.assertEqual(scrubber.scrub({key: "hunter2"})[key], REDACTED)

    def test_a_credential_under_a_prefixed_key_is_caught(self):
        # Without substring matching, every framework's naming convention would
        # have to be enumerated.
        out = scrubber.scrub({
            "user_password": "x",
            "stripe_api_key": "y",
            "x_auth_token": "z",
            "db_password": "w",
        })
        for value in out.values():
            self.assertEqual(value, REDACTED)

    def test_ordinary_fields_are_left_alone(self):
        # The other half of the promise: over-redaction makes the product worse
        # at its job for no security benefit.
        payload = {
            "user_id": "42",
            "order_id": "A-1001",
            "email": "someone@example.com",
            "ip_address": "203.0.113.9",
            "path": "/api/orders",
            "status_code": 500,
        }
        self.assertEqual(scrubber.scrub(payload), payload)

    def test_the_session_identifier_is_not_redacted(self):
        # It normalises to "sessionid", which the denylist would otherwise
        # catch - and must not, because it is how a session is recognised
        # across events. It arrives already hashed.
        hashed = hash_session_id("abc")
        self.assertEqual(scrubber.scrub({"session_id": hashed})["session_id"], hashed)

    def test_extra_denied_keys_are_accepted(self):
        custom = Scrubber(deny_keys=["internal_ref"])
        out = custom.scrub({"internal_ref": "abc", "user_id": "1"})
        self.assertEqual(out["internal_ref"], REDACTED)
        self.assertEqual(out["user_id"], "1")

    def test_scrubbing_can_be_turned_off(self):
        off = Scrubber(enabled=False)
        self.assertEqual(off.scrub({"password": "x"})["password"], "x")


class ValuePatternTests(unittest.TestCase):
    def test_a_jwt_is_removed_wherever_it_appears(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        out = scrub_string(f"token={jwt} rest")
        self.assertIn(REDACTED, out)
        self.assertNotIn(jwt, out)

    def test_provider_keys_are_removed_by_prefix(self):
        secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "xoxb-123456789012-abcdefghijkl",
            "sk_live_abcdefghij1234567890",
            "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
            "glpat-abcdefghij1234567890",
        ]
        for secret in secrets:
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, scrub_string(f"value {secret} end"))

    def test_a_private_key_block_is_removed_entirely(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nlines\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIEow", scrub_string(f"config: {pem}"))

    def test_credentials_in_a_url_are_removed(self):
        out = scrub_string("connecting to postgres://admin:s3cret@db.internal:5432/app")
        self.assertNotIn("s3cret", out)
        self.assertIn("db.internal", out)

    def test_an_authorization_value_in_free_text_is_removed(self):
        out = scrub_string("upstream said: Bearer abcdefghijklmnopqrstuvwxyz")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", out)


class CardTests(unittest.TestCase):
    def test_a_real_card_number_is_redacted(self):
        for card in ("4111111111111111", "4111 1111 1111 1111", "5500-0000-0000-0004"):
            with self.subTest(card=card):
                self.assertIn(REDACTED, scrub_string(f"paid with {card}"))

    def test_numbers_that_are_not_cards_are_left_alone(self):
        # Luhn is what keeps this from redacting order numbers, timestamps and
        # database ids - which would make the product worse at its job for
        # nothing.
        for value in ("4111111111111112", "1234567890123", "1700000000000000"):
            with self.subTest(value=value):
                self.assertIn(value, scrub_string(f"ref {value}"))

    def test_short_numbers_are_untouched(self):
        self.assertEqual(scrub_string("order 4821 total 1999"), "order 4821 total 1999")


class WalkTests(unittest.TestCase):
    def test_nested_values_are_reached(self):
        out = scrubber.scrub({
            "request": {"headers": {"authorization": "Bearer abc"}, "body": {"password": "x"}}
        })
        self.assertEqual(out["request"]["headers"]["authorization"], REDACTED)
        self.assertEqual(out["request"]["body"]["password"], REDACTED)

    def test_values_inside_lists_are_reached(self):
        out = scrubber.scrub({"users": [{"name": "a", "password": "x"}]})
        self.assertEqual(out["users"][0]["password"], REDACTED)
        self.assertEqual(out["users"][0]["name"], "a")

    def test_a_cycle_is_survived(self):
        # A request object graph or a self-referencing logging extra. This must
        # end in a truncated event rather than a recursion error in the SDK.
        node = {"name": "root"}
        node["self"] = node
        self.assertIn("circular", str(scrubber.scrub(node)))

    def test_depth_is_bounded(self):
        deep = {"password": "x"}
        for _ in range(30):
            deep = {"nested": deep}
        self.assertIn("max-depth", str(scrubber.scrub(deep)))

    def test_the_number_of_items_is_bounded(self):
        wide = {f"k{i}": i for i in range(MAX_ITEMS + 50)}
        out = scrubber.scrub(wide)
        self.assertLessEqual(len(out), MAX_ITEMS + 1)
        self.assertIn("[secploy:truncated]", out)

    def test_an_object_that_cannot_be_stringified_is_redacted(self):
        class Hostile:
            def __str__(self):
                raise RuntimeError("nope")

            __repr__ = __str__

        # Never raises, and the unrenderable value does not go out as-is.
        self.assertEqual(scrubber.scrub(Hostile()), REDACTED)

    def test_scrubbing_never_raises(self):
        for value in (None, object(), 42, b"bytes", {1, 2, 3}, (1, 2)):
            with self.subTest(value=type(value).__name__):
                scrubber.scrub(value)


class NormalizeKeyTests(unittest.TestCase):
    def test_naming_style_is_erased(self):
        for key in ("API_KEY", "api-key", "apiKey", "Api Key"):
            self.assertEqual(normalize_key(key), "apikey")


class SessionHashTests(unittest.TestCase):
    def test_it_is_stable_unique_and_not_reversible(self):
        self.assertEqual(hash_session_id("abc"), hash_session_id("abc"))
        self.assertNotEqual(hash_session_id("abc"), hash_session_id("abd"))
        self.assertNotIn("abc", hash_session_id("abc"))
        self.assertRegex(hash_session_id("abc"), r"^sess_[0-9a-f]{32}$")

    def test_it_is_idempotent(self):
        # Auth context is normalised at more than one layer; hashing twice would
        # produce a value that matches no control, and the gate would silently
        # stop enforcing.
        once = hash_session_id("abc")
        self.assertEqual(hash_session_id(once), once)

    def test_an_empty_value_stays_empty(self):
        for value in ("", None):
            self.assertEqual(hash_session_id(value), "")

    def test_it_matches_the_node_sdk(self):
        # Both SDKs feed one ingest. If they hashed differently, one session
        # reported by two services would look like two, and correlation would
        # silently split. Pinned against sha256("abc")[:32].
        self.assertEqual(
            hash_session_id("abc"),
            "sess_ba7816bf8f01cfea414140de5dae2223",
        )


class EventBoundaryTests(unittest.TestCase):
    def make_handler(self, before_send=None, scrubber_obj=None):
        q = queue.Queue(maxsize=100)
        return q, EventHandler(q, scrubber=scrubber_obj, before_send=before_send)

    def test_every_event_is_scrubbed_whatever_produced_it(self):
        # Scrubbing lives here rather than at each call site, because redacting
        # per call site guarantees the next payload someone adds is the one that
        # leaks.
        q, handler = self.make_handler()
        handler.send_event("error", {"context": {"password": "hunter2", "user_id": "1"}})

        payload = q.get_nowait()["payload"]
        self.assertEqual(payload["context"]["password"], REDACTED)
        self.assertEqual(payload["context"]["user_id"], "1")

    def test_a_hook_can_drop_an_event(self):
        q, handler = self.make_handler(before_send=lambda payload: None)
        self.assertFalse(handler.send_event("error", {"message": "x"}))
        self.assertTrue(q.empty())
        self.assertEqual(handler.filtered_events, 1)

    def test_a_hook_sees_the_real_values(self):
        # It runs first so it can decide from them - drop the event, annotate
        # it, redact something only this codebase knows is sensitive.
        seen = {}

        def hook(payload):
            seen.update(payload)
            return payload

        _, handler = self.make_handler(before_send=hook)
        handler.send_event("error", {"context": {"password": "hunter2"}})

        self.assertEqual(seen["context"]["password"], "hunter2")

    def test_scrubbing_runs_after_the_hook(self):
        # So nothing the hook returned - including anything it added - escapes.
        q, handler = self.make_handler(
            before_send=lambda payload: {**payload, "extra": {"api_key": "leaked"}}
        )
        handler.send_event("error", {"message": "x"})

        self.assertEqual(q.get_nowait()["payload"]["extra"]["api_key"], REDACTED)

    def test_a_hook_that_raises_does_not_lose_the_event(self):
        # A broken filter should cost visibility into the filter, not into the
        # application.
        def hook(payload):
            raise RuntimeError("hook is broken")

        q, handler = self.make_handler(before_send=hook)
        self.assertTrue(handler.send_event("error", {"message": "x"}))
        self.assertFalse(q.empty())

    def test_a_hook_returning_nonsense_does_not_lose_the_event(self):
        q, handler = self.make_handler(before_send=lambda payload: "not a dict")
        self.assertTrue(handler.send_event("error", {"message": "x"}))
        self.assertFalse(q.empty())

    def test_an_event_id_is_still_stamped_after_scrubbing(self):
        q, handler = self.make_handler()
        handler.send_event("error", {"message": "x"})
        self.assertTrue(q.get_nowait()["payload"]["event_id"])


if __name__ == "__main__":
    unittest.main()
