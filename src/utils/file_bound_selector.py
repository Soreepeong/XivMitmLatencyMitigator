import selectors
import typing
import socket


class FileBoundSelector:
    def __init__(self,
                 selector: selectors.BaseSelector,
                 sock: socket.socket,
                 event_in: bool,
                 event_out: bool,
                 event_cb: typing.Callable[[int], None]):
        self._selector = selector
        self._sock = sock
        self._event_in = event_in
        self._event_out = event_out
        self._event_cb = event_cb

        eventmask = (
                0
                | (selectors.EVENT_READ if self._event_in else 0)
                | (selectors.EVENT_WRITE if self._event_out else 0)
        )
        self._selector.register(self._sock, eventmask, self._event_cb)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._selector.unregister(self._sock)

    def modify(self,
               event_in: bool | None = None,
               event_out: bool | None = None,
               new_cb: typing.Callable[[int], None] = None):
        changed = False
        if event_in is not None and event_in != self._event_in:
            self._event_in = event_in
            changed = True
        if event_out is not None and event_out != self._event_out:
            self._event_out = event_out
            changed = True
        if new_cb is not None and new_cb != self._event_cb:
            self._event_cb = new_cb
            changed = True

        if changed:
            eventmask = (
                    0
                    | (selectors.EVENT_READ if self._event_in else 0)
                    | (selectors.EVENT_WRITE if self._event_out else 0)
            )
            self._selector.modify(self._sock, eventmask, self._event_cb)
