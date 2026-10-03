import json
import logging
import uuid

from starlette.responses import JSONResponse

MAX_REQUEST_BYTES = 1_048_576
logger = logging.getLogger("uvicorn.error.requests")


class RequestSafety:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = f"req-{uuid.uuid4()}"
        scope.setdefault("state", {})["request_id"] = request_id
        status = 500
        started = False

        async def safe_send(message):
            nonlocal status, started
            if message["type"] == "http.response.start":
                status = message["status"]
                started = True
                message["headers"] = [*message.get("headers", []),
                                      (b"x-request-id", request_id.encode())]
            await send(message)

        try:
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                    await JSONResponse({"detail": "request body too large"}, 413)(
                        scope, receive, safe_send
                    )
                    return
                body.extend(chunk)
                if not message.get("more_body", False):
                    break
            delivered = False

            async def buffered_receive():
                nonlocal delivered
                if delivered:
                    return await receive()
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            await self.app(scope, buffered_receive, safe_send)
        except Exception:
            if not started:
                await JSONResponse({"detail": "internal server error"}, 500)(
                    scope, receive, safe_send
                )
        finally:
            logger.info(json.dumps({
                "request_id": request_id, "status": status,
                "category": "server_error" if status >= 500 else
                            "request_rejected" if status >= 400 else "success",
            }))
