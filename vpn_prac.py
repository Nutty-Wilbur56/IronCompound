import threading
import time

class ThreadCounter:

    def __init__(self):
        self.counter = 0
        self.lock = threading.Lock()

    def count(self, thread_no):
        while True:
            self.lock.acquire()
            self.counter += 1
            print(f"{thread_no}: Just increased counter to {self.counter}")
            time.sleep(0.5)
            print(f"{thread_no}: Done some work, now value is: {self.counter}")
            self.lock.release()

tc = ThreadCounter()

for i in range(10):
    t = threading.Thread(target=tc.count, args=(i,))
    t.start()