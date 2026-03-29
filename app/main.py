"""FencePost — multi-host UFW management dashboard."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature

from .ssh_client import load_config, fetch_all_hosts, fetch_single_host
from .eventfeed import detect_and_notify
from .diagnose import diagnose_connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FencePost", docs_url=None, redoc_url=None)

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

def _to_localtime(dt: datetime) -> datetime:
    """Convert a datetime to the configured local timezone."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_local_tz)

templates.env.filters["localtime"] = _to_localtime

# Config
CONFIG_PATH = os.environ.get("FENCEPOST_CONFIG", "config.yaml")
USERNAME = os.environ.get("FENCEPOST_USERNAME", "admin")
PASSWORD = os.environ.get("FENCEPOST_PASSWORD", "fencepost")
SECRET_KEY = os.environ.get("FENCEPOST_SECRET_KEY", "change-me")
SESSION_MAX_AGE = 86400 * 7  # 7 days

serializer = URLSafeTimedSerializer(SECRET_KEY)

# Timezone from config (falls back to UTC)
_initial_config = load_config(CONFIG_PATH)
_local_tz = ZoneInfo(_initial_config.get("timezone", "UTC"))

# In-memory cache of last fetch
_cached_states: list = []
_last_fetch: datetime | None = None


def _get_config() -> dict:
    return load_config(CONFIG_PATH)


def _get_session_user(request: Request) -> str | None:
    token = request.cookies.get("fencepost_session")
    if not token:
        return None
    try:
        return serializer.loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None


def require_auth(request: Request) -> str:
    user = _get_session_user(request)
    if not user:
        raise _redirect_login()
    return user


class _redirect_login(Exception):
    pass


@app.exception_handler(_redirect_login)
async def redirect_login_handler(request: Request, exc: _redirect_login):
    return RedirectResponse(url="/login", status_code=303)


# --- Auth routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _get_session_user(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == USERNAME and password == PASSWORD:
        token = serializer.dumps(username)
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            "fencepost_session",
            token,
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("fencepost_session")
    return response


# --- Dashboard routes ---

@app.get("/", response_class=HTMLResponse)
async def overview(request: Request, user: str = Depends(require_auth)):
    global _cached_states, _last_fetch

    config = _get_config()
    states = fetch_all_hosts(config)
    _cached_states = states
    _last_fetch = datetime.now(timezone.utc)

    # Notify EventFeed of changes
    nf = config.get("notifications", {})
    nf_api_key = os.environ.get("NOTIFICATIONS_API_KEY", nf.get("api_key", ""))
    if nf.get("url") and nf_api_key:
        try:
            detect_and_notify(states, nf["url"], nf_api_key, nf.get("channel", "fencepost"))
        except Exception as e:
            logger.error("EventFeed notification failed: %s", e)

    return templates.TemplateResponse("overview.html", {
        "request": request,
        "hosts": states,
        "last_fetch": _last_fetch,
        "user": user,
    })


@app.get("/host/{host_name}", response_class=HTMLResponse)
async def host_detail(request: Request, host_name: str, user: str = Depends(require_auth)):
    config = _get_config()
    state = fetch_single_host(config, host_name)

    if not state:
        return HTMLResponse("Host not found", status_code=404)

    # Update cache
    global _cached_states
    _cached_states = [s if s.name != host_name else state for s in _cached_states]

    return templates.TemplateResponse("host_detail.html", {
        "request": request,
        "host": state,
        "user": user,
    })


@app.get("/diagnose", response_class=HTMLResponse)
async def diagnose_page(request: Request, user: str = Depends(require_auth)):
    config = _get_config()
    hosts = config.get("hosts", [])
    devices = config.get("devices", [])

    return templates.TemplateResponse("diagnose.html", {
        "request": request,
        "hosts": hosts,
        "devices": devices,
        "result": None,
        "user": user,
    })


@app.post("/diagnose", response_class=HTMLResponse)
async def diagnose_submit(
    request: Request,
    source_ip: str = Form(...),
    dest_host: str = Form(...),
    dest_port: int = Form(...),
    dest_protocol: str = Form("tcp"),
    user: str = Depends(require_auth),
):
    config = _get_config()

    # Fetch fresh state for the target host
    state = fetch_single_host(config, dest_host)
    if not state:
        return HTMLResponse("Host not found", status_code=404)

    network_names = config.get("networks", {})
    result = diagnose_connection(state, source_ip, dest_port, dest_protocol, network_names)

    hosts = config.get("hosts", [])
    devices = config.get("devices", [])

    return templates.TemplateResponse("diagnose.html", {
        "request": request,
        "hosts": hosts,
        "devices": devices,
        "result": result,
        "user": user,
    })


@app.post("/refresh", response_class=HTMLResponse)
async def refresh_all(request: Request, user: str = Depends(require_auth)):
    return RedirectResponse(url="/", status_code=303)


@app.post("/refresh/{host_name}", response_class=HTMLResponse)
async def refresh_host(request: Request, host_name: str, user: str = Depends(require_auth)):
    return RedirectResponse(url=f"/host/{host_name}", status_code=303)
