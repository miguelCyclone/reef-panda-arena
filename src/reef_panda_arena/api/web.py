"""Serve the local browser interface from the installed package."""

from importlib.resources import files

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
    "script-src 'self'; style-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


def mount_web(app: FastAPI) -> None:
    web_dir = str(files("reef_panda_arena.web"))
    app.mount("/assets", StaticFiles(directory=web_dir), name="web-assets")

    @app.get("/", include_in_schema=False)
    async def home() -> FileResponse:
        return FileResponse(
            f"{web_dir}/booking.html",
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": CONTENT_SECURITY_POLICY,
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/library", include_in_schema=False)
    async def library() -> FileResponse:
        return FileResponse(f"{web_dir}/index.html", headers={
            "Cache-Control": "no-store", "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "X-Content-Type-Options": "nosniff"})
