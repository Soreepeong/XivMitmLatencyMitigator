import typing

T = typing.TypeVar("T")

def clamp(v: T, min_: T, max_: T) -> T:
    return max(min_, min(max_, v))
