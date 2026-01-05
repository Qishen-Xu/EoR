import threading
import time

class AdaptiveRetry:
    """Adaptive Retry - Thread Safe Version"""
    def __init__(self):
        self.failure_counts = {}
        self.lock = threading.Lock()

    def get_retry_params(self, api_name: str):
        with self.lock:
            failures = self.failure_counts.get(api_name, 0)
        max_retries = min(5, 3 + failures // 2)
        base_delay = min(15, 3 * (1.5 ** failures))
        return max_retries, base_delay

    def record_failure(self, api_name: str):
        with self.lock:
            self.failure_counts[api_name] = self.failure_counts.get(api_name, 0) + 1

    def record_success(self, api_name: str):
        with self.lock:
            self.failure_counts[api_name] = 0
