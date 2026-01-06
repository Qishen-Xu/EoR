import threading
import time

class RateLimiter:
    def __init__(self, max_calls_per_second):
        self.interval = 1.0 / max_calls_per_second
        self.last_call_timestamp = 0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_call_timestamp
            wait_time = self.interval - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
            self.last_call_timestamp = time.time()
