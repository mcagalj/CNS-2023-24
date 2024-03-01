from pathlib import Path

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import tls

router = APIRouter(prefix=tls.prefix, tags=["TLS Client Authentication"])


BASE_PATH = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_PATH / ".." / "templates"))


@router.get("/public", response_class=HTMLResponse)
async def public_path(request: Request):
    return templates.TemplateResponse(
        "template2.html",
        {
            "request": request,
            "title": "TLS Client Authentication - public",
        },
    )


@router.get("/protected", response_class=HTMLResponse)
async def protected_path(request: Request):
    ssl_client_s_cn = request.headers.get("X-SSL-Client-Cert-CN", None)
    # print(f"ssl_client_s_cn: {ssl_client_s_cn}")

    if ssl_client_s_cn is not None:
        return templates.TemplateResponse(
            "template2.html",
            {
                "request": request,
                "title": "TLS Client Authentication - protected",
                "username": ssl_client_s_cn,
            },
        )

    return templates.TemplateResponse(
        "unauthorized.html",
        {
            "request": request,
            "title": "401 - Unauthorized",
        },
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
