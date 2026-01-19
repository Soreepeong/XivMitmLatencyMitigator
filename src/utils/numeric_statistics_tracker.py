import collections
import math
import time


class NumericStatisticsTracker:
    def __init__(self, count: int, max_age: float | None = None):
        self._count = count
        self._max_age = max_age
        self._values = collections.deque()
        self._expiry = collections.deque()

    def add(self, v: float):
        self._values.append(v)
        if self._max_age is not None:
            self._expiry.append(time.time() + self._max_age)
        while len(self._values) > self._count:
            self._values.popleft()
            if self._max_age is not None:
                self._expiry.popleft()

    def min(self) -> float | None:
        return min(self._values) if self._values else None

    def max(self) -> float | None:
        return max(self._values) if self._values else None

    def mean(self) -> float | None:
        return sum(self._values) / len(self._values) if self._values else None

    def median(self) -> float | None:
        if not self._values:
            return None
        s = list(sorted(self._values))
        if len(s) % 2 == 0:
            return (s[len(s) // 2] + s[len(s) // 2 - 1]) / 2
        else:
            return s[len(s) // 2]

    def deviation(self) -> float | None:
        if not self._values:
            return None
        mean = self.mean()
        return math.sqrt(sum(pow(x - mean, 2) for x in self._values) / len(self._values))

    def __bool__(self):
        return not not self._values
