"""A previously verified lease must not authorize a later write after ownership changes."""
import tempfile
import unittest
from pathlib import Path

from test_device_transaction import StubDevice


class LeaseRevalidationTest(unittest.TestCase):
    def test_rechecks_ownership_after_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            device = StubDevice(Path(directory))
            result = device.run('''
                lock_take >/dev/null || exit 9
                lock_require || exit 9
                printf 'OTHER-ACTIVE 2099-01-01T00:00:00Z\n' > "$LOCK_PATH"
                if lock_require; then echo UNSAFE; exit 1; fi
                grep -q OTHER-ACTIVE "$LOCK_PATH"
            ''')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rechecks_expiry_after_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            device = StubDevice(Path(directory))
            result = device.run('''
                lock_take >/dev/null || exit 9
                lock_require || exit 9
                sed 's/^renewed=.*/renewed=1/' "$LOCK_STATE_DIR/meta" > "$LOCK_STATE_DIR/expired"
                mv "$LOCK_STATE_DIR/expired" "$LOCK_STATE_DIR/meta"
                if lock_require; then echo UNSAFE; exit 1; fi
            ''')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
