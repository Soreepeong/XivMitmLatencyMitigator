import asyncio
import subprocess

CONNECTION_ERRORS = {asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError}


class SubprocessFailedError(RuntimeError):
    def __init__(self, code: int):
        self.code = code

    @classmethod
    def raise_if_nonzero(cls, code: int):
        if code != 0:
            raise cls(code)

    @classmethod
    def call_or_raise(cls, shell_command: str):
        code = subprocess.call(shell_command, shell=True)
        cls.raise_if_nonzero(code)


class InvalidDataException(ValueError):
    pass


def find_nested_error[
    T1: BaseException | None = None,
    T2: BaseException | None = None,
    T3: BaseException | None = None,
    T4: BaseException | None = None
](
        e: BaseException,
        t1: type[T1] | None = None,
        t2: type[T2] | None = None,
        t3: type[T3] | None = None,
        t4: type[T4] | None = None,
) -> T1 | T2 | T3 | T4 | None:
    for error_type in t1, t2, t3, t4:
        if error_type is None:
            continue
        if isinstance(e, error_type):
            return e
        if isinstance(e, BaseExceptionGroup):
            for e2 in e.exceptions:
                if isinstance(e2, error_type):
                    return e2
    return None
