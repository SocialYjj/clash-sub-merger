"""Low-level HTTP middleware used at the application boundary."""

from starlette.responses import JSONResponse


class _RequestTooLarge(Exception):
    """Internal signal raised by the streaming receive wrapper."""


class RequestSizeLimitMiddleware:
    """Reject oversized bodies, including chunked requests without Content-Length."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        try:
            content_length_values = [
                value.decode("ascii", errors="strict")
                for name, value in scope.get("headers", [])
                if name.lower() == b"content-length"
            ]
            if len(content_length_values) > 1:
                raise ValueError
            content_length_value = content_length_values[0] if content_length_values else None
            if content_length_value is not None:
                content_length = int(content_length_value)
                if content_length < 0:
                    raise ValueError
                if content_length > self.max_bytes:
                    await JSONResponse(
                        status_code=413,
                        content={"detail": "Request body is too large"},
                    )(scope, receive, send)
                    return
        except (UnicodeDecodeError, ValueError):
            await JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header"},
            )(scope, receive, send)
            return

        received_bytes = 0

        async def limited_receive():
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_bytes:
                    raise _RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestTooLarge:
            await JSONResponse(
                status_code=413,
                content={"detail": "Request body is too large"},
            )(scope, receive, send)
