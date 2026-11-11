"""Regression: the log privacy filter must also redact tracebacks."""
import io
import logging
import unittest

from ovb_rc003 import logging_setup


class PrivacyFilterTracebackTests(unittest.TestCase):
    def _emit(self, logger, msg, exc=None):
        stream = io.StringIO()
        h = logging.StreamHandler(stream)
        h.addFilter(logging_setup._PrivacyFilter())
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        try:
            if exc is not None:
                logger.exception(msg, exc_info=exc)
            else:
                logger.info(msg)
        finally:
            logger.removeHandler(h)
        return stream.getvalue()

    def test_msg_with_mac_is_redacted(self):
        logger = logging.getLogger("test.redact.msg")
        logger.setLevel(logging.INFO)
        out = self._emit(logger, "AA:BB:CC:DD:EE:FF")
        self.assertNotIn("AA:BB:CC:DD:EE:FF", out)
        self.assertIn("[redacted]", out)

    def test_exception_traceback_with_device_id_is_redacted(self):
        logger = logging.getLogger("test.redact.exc")
        logger.setLevel(logging.INFO)
        try:
            raise RuntimeError("BluetoothLE#BluetoothAA:BB:CC:DD:EE:FF-failed")
        except RuntimeError as exc:
            out = self._emit(logger, "connection failed", exc=(type(exc), exc, exc.__traceback__))
        self.assertNotIn("AA:BB:CC:DD:EE:FF", out)
        self.assertNotIn("BluetoothLE#Bluetooth", out)
        self.assertIn("[redacted]", out)


if __name__ == "__main__":
    unittest.main()
