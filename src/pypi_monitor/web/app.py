"""The dashboard. Names, evidence and code on its pages come from attackers.

So templates escape everything, the Content-Security-Policy allows no inline code, and a page on
another site can neither read the dashboard (Host check) nor label releases: a cross-site form
cannot set `HX-Request`. There is no login: the service is reachable from this machine only.
"""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pypi_monitor.db.session import Sessions, create_engine, create_sessions
from pypi_monitor.domain import Label
from pypi_monitor.pipeline.unpack import UnpackLimits
from pypi_monitor.settings import Settings
from pypi_monitor.storage import ArtifactStorage
from pypi_monitor.web.diff import release_diff
from pypi_monitor.web.pypi_report import report_text
from pypi_monitor.web.queries import (
    LabelFilter,
    LevelFilter,
    add_label,
    feed,
    release_card,
    stored_artifacts,
)

_HERE = Path(__file__).parent
MAX_COMMENT_LENGTH = 2000
MAX_SEARCH_LENGTH = 255
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _require_htmx(hx_request: Annotated[str | None, Header()] = None) -> None:
    if hx_request != "true":
        raise HTTPException(403, "label through the dashboard")


def create_app(
    sessions: Sessions,
    storage: ArtifactStorage,
    limits: UnpackLimits,
    allowed_hosts: list[str],
    engine: AsyncEngine | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if engine is not None:
            await engine.dispose()

    app = FastAPI(
        title="PyPI Supply Chain Monitor", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    app.openapi_url = None
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
    templates = Jinja2Templates(directory=_HERE / "templates")

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        return response

    def render(request: Request, name: str, **context: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, context)

    async def load_card(release_id: int) -> Any:
        card = await release_card(sessions, release_id)
        if card is None:
            raise HTTPException(404, "unknown release")
        return card

    @app.get("/", response_class=HTMLResponse)
    async def index(
        request: Request,
        level: LevelFilter = LevelFilter.ALERTS,
        label: LabelFilter = LabelFilter.NONE,
        q: Annotated[str, Query(max_length=MAX_SEARCH_LENGTH)] = "",
        page: Annotated[int, Query(ge=1)] = 1,
        hx_request: Annotated[str | None, Header()] = None,
    ) -> HTMLResponse:
        found = await feed(sessions, level, label, q.strip(), page)
        template = "_rows.html" if hx_request == "true" else "feed.html"
        response = render(request, template, feed=found, level=level, label=label, q=q, page=page)
        # The same address answers with a page or a fragment, and caches must not mix them up.
        response.headers["Vary"] = "HX-Request"
        return response

    @app.get("/releases/{release_id}", response_class=HTMLResponse)
    async def release(request: Request, release_id: int) -> HTMLResponse:
        return render(request, "release.html", card=await load_card(release_id))

    @app.get("/releases/{release_id}/diff", response_class=HTMLResponse)
    async def diff(request: Request, release_id: int) -> HTMLResponse:
        card = await load_card(release_id)
        new = await stored_artifacts(sessions, release_id)
        old = await stored_artifacts(sessions, card.release.prev_release_id)
        result = await asyncio.to_thread(release_diff, new, old, storage, limits)
        return render(request, "diff.html", card=card, diff=result)

    @app.get("/releases/{release_id}/report", response_class=HTMLResponse)
    async def pypi_report(request: Request, release_id: int) -> HTMLResponse:
        card = await load_card(release_id)
        return render(request, "report.html", card=card, text=report_text(card))

    @app.post(
        "/releases/{release_id}/label",
        response_class=HTMLResponse,
        dependencies=[Depends(_require_htmx)],
    )
    async def label_release(
        request: Request,
        release_id: int,
        label: Annotated[Label, Form()],
        comment: Annotated[str, Form(max_length=MAX_COMMENT_LENGTH)] = "",
    ) -> HTMLResponse:
        card = await load_card(release_id)
        if card.verdict is None:
            raise HTTPException(409, "the release has no verdict yet")
        await add_label(sessions, card.verdict, label, comment.strip() or None)
        return render(request, "_label.html", card=await load_card(release_id))

    return app


def app_from_settings(settings: Settings) -> FastAPI:
    engine = create_engine(settings.database_url.get_secret_value())
    return create_app(
        create_sessions(engine),
        ArtifactStorage(
            settings.s3_endpoint,
            settings.s3_access_key.get_secret_value(),
            settings.s3_secret_key.get_secret_value(),
            settings.s3_bucket,
        ),
        UnpackLimits(
            settings.max_unpacked_bytes,
            settings.max_unpacked_files,
            settings.max_compression_ratio,
        ),
        settings.dashboard_allowed_hosts,
        engine,
    )
