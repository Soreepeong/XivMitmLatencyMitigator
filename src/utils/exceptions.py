class RootRequiredError(RuntimeError):
    pass


class InvalidDataException(ValueError):
    pass


def is_error_nested(e: BaseException, *error_types: type[BaseException]):
    for error_type in error_types:
        if isinstance(e, error_type):
            return e
        if isinstance(e, BaseExceptionGroup):
            for e2 in e.exceptions:
                if isinstance(e2, error_type):
                    return e2
    return None
