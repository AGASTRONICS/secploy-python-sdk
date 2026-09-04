"""
A guard against configuration that does not do anything.

Three separate settings in this project turned out to be declared, defaulted,
validated and never read - ``sampling_rate``, ``max_queue_size``, and the
ingest's rate limit. Each was found by accident, months apart, and each had been
quietly lying to whoever set it: a sample rate that sampled nothing, a bound
that bounded nothing.

Fixing them one at a time does not stop a fourth. This does.
"""

import ast
import pathlib
import unittest

from secploy.lib.config import DEFAULT_CONFIG

PACKAGE = pathlib.Path(__file__).resolve().parent.parent / "secploy"

# The declaration itself is not a use, or every option would look read.
DECLARING_FILES = {"config.py"}


def _identifiers_read():
    """Every name that appears as an attribute or a string key in the package."""
    seen = set()

    for path in PACKAGE.rglob("*.py"):
        if path.name in DECLARING_FILES:
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            # config.batch_size / self.batch_size
            if isinstance(node, ast.Attribute):
                seen.add(node.attr)
            # getattr(config, "batch_size", ...) and config["batch_size"]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                seen.add(node.value)

    return seen


class ConfigIsLiveTests(unittest.TestCase):
    def test_every_option_is_actually_read(self):
        read = _identifiers_read()

        dead = sorted(name for name in DEFAULT_CONFIG if name not in read)

        self.assertEqual(
            dead, [],
            "\n\nThese options are declared and never read, so setting them does "
            "nothing:\n  " + "\n  ".join(dead) +
            "\n\nEither use the value or remove it from DEFAULT_CONFIG. An option "
            "that\nsilently has no effect is worse than one that does not exist, "
            "because\nsomebody will set it and believe it worked.\n"
        )

    def test_the_guard_would_notice_a_new_dead_option(self):
        # A guard that cannot fail is not a guard. This proves the check has
        # teeth without leaving a dead option in the real configuration.
        read = _identifiers_read()
        self.assertNotIn("a_setting_nobody_reads", read)

    def test_retired_options_are_folded_rather_than_ignored(self):
        from secploy.lib.config import migrate_retired_options

        # retry_attempts was validated and shadowed by max_retry, which is the
        # one the transport reads. Setting it passed validation and changed
        # nothing.
        migrated = migrate_retired_options({"retry_attempts": 9})
        self.assertEqual(migrated, {"max_retry": 9})

        # An explicit max_retry wins; the alias does not override it.
        migrated = migrate_retired_options({"retry_attempts": 9, "max_retry": 3})
        self.assertEqual(migrated["max_retry"], 3)

        # The rest are dropped rather than carried forward.
        migrated = migrate_retired_options(
            {"ignore_errors": True, "source_root": "/app", "heartbeat_interval": 30}
        )
        self.assertEqual(migrated, {})

    def test_a_config_setting_a_retired_option_still_loads(self):
        # Removing an option must not start rejecting configurations that were
        # valid yesterday.
        from secploy.lib.config import migrate_retired_options

        # The real order: migrate what the file said, then merge over the
        # defaults. Migrating the merged dict instead would find max_retry
        # already present and never apply the alias.
        file_config = {"retry_attempts": 4, "ignore_errors": False, "batch_size": 25}

        merged = dict(DEFAULT_CONFIG)
        merged.update(migrate_retired_options(file_config))

        self.assertEqual(merged["batch_size"], 25)
        self.assertEqual(merged["max_retry"], 4)
        self.assertNotIn("ignore_errors", merged)


if __name__ == "__main__":
    unittest.main()
