from typing import Union  # noqa: F401

from .ifuzz_logger import IFuzzLogger


class FuzzLogger(IFuzzLogger):
    """
    Takes a list of IFuzzLogger objects and multiplexes logged data to each one.

    FuzzLogger also maintains summary failure and error data.

    Args:
        fuzz_loggers (:obj:`list` of :obj:`IFuzzLogger`): IFuzzLogger objects
                                                          to which to send log data.
    """

    def __init__(self, fuzz_loggers=None):
        if fuzz_loggers is None:
            fuzz_loggers = []
        self._fuzz_loggers = fuzz_loggers

        self._cur_test_case_id = ""  # type: Union[int, str]
        self._cur_test_case_name = ""
        self._cur_test_case_path = ""
        self.failed_test_cases = {}
        self.error_test_cases = []
        self.passed_test_case_count = 0  # passed test cases are simply counted to avoid runaway memory usage
        self._last_passed_id = ""  # helps avoid duplicates
        self.test_case_count = 0

    @property
    def most_recent_test_id(self):
        """Return a value (e.g. string) representing the most recent test case."""
        return self._cur_test_case_id

    def open_test_step(self, description):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.open_test_step(description=description)

    def log_error(self, rawpkt):
        self.error_test_cases.append(rawpkt)
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_error(self._cur_test_case_name, self._cur_test_case_path, rawpkt=rawpkt)

    def log_fail(self, description=""):
        if self._cur_test_case_id not in self.failed_test_cases:
            self.failed_test_cases[self._cur_test_case_id] = []
        self.failed_test_cases[self._cur_test_case_id].append(description)
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_fail(description=description)

    def log_info(self, description):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_info(description=description)

    def log_recv(self, data):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_recv(data=data)

    def log_pass(self, description=""):
        if self._cur_test_case_id != self._last_passed_id:
            self.passed_test_case_count += 1
            self._last_passed_id = self._cur_test_case_id
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_pass(description=description)

    def log_check(self, description):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_check(description=description)

    def open_test_case(self, packet_name, path):
        self._cur_test_case_name = packet_name
        self._cur_test_case_path = path
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.open_test_case(name = packet_name, cur_path = path)

    def log_test_case(self, packet_test_case_id, packet_name, rawpkt):
        self._cur_test_case_id = packet_test_case_id
        self.test_case_count += 1
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_test_case(name = packet_name, rawpkt = rawpkt)

    def log_send(self, data):
        self.test_case_count += 1
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_send(data=data)

    def close_test_case(self):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.close_test_case()

    def close_test(self):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.close_test()

    def failure_summary(self):
        """Return test summary string based on fuzz logger results.

        :return: Test summary string, may be multi-line.
        """
        summary = "Test Summary: {0} tests ran.\n".format(self.test_case_count)
        summary += "PASSED: {0} test cases.\n".format(self.passed_test_case_count)

        if len(self.failed_test_cases) > 0:
            summary += "FAILED: {0} test cases:\n".format(len(self.failed_test_cases))
            summary += "{0}\n".format("\n".join(map(str, self.failed_test_cases)))

        if len(self.error_test_cases) > 0:
            summary += "Errors on {0} test cases:\n".format(len(self.error_test_cases))
            summary += "{0}".format("\n".join(map(str, self.error_test_cases)))

        return summary
