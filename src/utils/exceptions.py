import typing


class SubprocessFailedError(RuntimeError):
    def __init__(self, code: int):
        self.code = code

    @classmethod
    def raise_if_nonzero(cls, code: int):
        if code != 0:
            raise cls(code)


class InvalidDataException(ValueError):
    pass


@typing.overload
def find_nested_error[T: BaseException](e: BaseException, t1: type[T], /) -> T | None: ...
@typing.overload
def find_nested_error[T1: BaseException, T2: BaseException](e: BaseException, t1: type[T1], t2: type[T2], /) -> T1 | T2 | None: ...
@typing.overload
def find_nested_error[T1: BaseException, T2: BaseException, T3: BaseException](e: BaseException, t1: type[T1], t2: type[T2], t3: type[T3], /) -> T1 | T2 | T3 | None: ...
def find_nested_error(e: BaseException, *error_types: type[BaseException]) -> BaseException | None:
    for error_type in error_types:
        if isinstance(e, error_type):
            return e
        if isinstance(e, BaseExceptionGroup):
            for e2 in e.exceptions:
                if isinstance(e2, error_type):
                    return e2
    return None


def find_expected_stop_error(e: BaseException) -> EOFError | StopIteration | None:
    return find_nested_error(e, EOFError, StopIteration)


class _SupportsClose(typing.Protocol):
    def close(self): ...


def close_ignore_errors(sock: _SupportsClose):
    # noinspection PyBroadException
    try:
        sock.close()
    except BaseException:
        pass
