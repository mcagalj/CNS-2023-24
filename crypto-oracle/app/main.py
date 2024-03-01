# q: how do i start the app?
# a: uvicorn app.main:app --reload

import importlib

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .config import LAB_ORDER, get_app_settings
from .routers import tls, ws, passkeys

# from .routers import arp, ecb, cbc

settings = get_app_settings()

app = FastAPI(
    title=settings.app_title,
    docs_url="/",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
)

# Normally, we would import routers as follows:
#   app.include_router(arp.router)
#   app.include_router(ecb.router)
#   app.include_router(cbc.router)
#
# This however sets the specific order of their appearance
# in the interactive automatic API documentation. Sometimes
# we would like to re-order labs and have this change
# reflected in the interactive API documentation.
for route in LAB_ORDER:
    router = importlib.import_module(f".routers.{route.scope}", package=__package__)
    app.include_router(router.router)

# Mount other routers
app.include_router(ws.router)
app.include_router(tls.router)
app.include_router(passkeys.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
