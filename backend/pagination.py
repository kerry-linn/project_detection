from typing import Annotated

from fastapi import Query, Response

PageLimit = Annotated[int, Query(ge=1, le=100)]
PageOffset = Annotated[int, Query(ge=0, le=1_000_000)]


def page_headers(response: Response, total: int, limit: int, offset: int) -> None:
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Next-Offset"] = str(offset + limit) if offset + limit < total else ""
