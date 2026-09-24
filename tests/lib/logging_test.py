import logging
import unittest
from io import StringIO

from aerleon.lib import logging as aerleon_logger


class TestLogHandler(unittest.TestCase):
    def setUp(self):
        self.log_capture_string = StringIO()
        self.test_handler = aerleon_logger.LogHandler(self.log_capture_string)
        self.test_handler.setFormatter(logging.Formatter(aerleon_logger.LOG_FORMAT))
        self.test_logger = logging.getLogger()
        self.test_logger.addHandler(self.test_handler)
        self.test_logger.setLevel(logging.DEBUG)

    def test_log_output(self):
        self.test_logger.info('once', extra={'emit_once': True})
        self.test_logger.info('once', extra={'emit_once': True})
        self.test_logger.info('twice')
        self.test_logger.info('twice')

        log_output = self.log_capture_string.getvalue()
        self.assertEqual(log_output.count('once'), 1)
        self.assertEqual(log_output.count('twice'), 2)

    def tearDown(self):
        self.test_logger.removeHandler(self.test_handler)
        self.test_logger.handlers = []


if __name__ == '__main__':
    unittest.main()
