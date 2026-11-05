"""Creates the FastAPI app, registers the router and the exception handlers."""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.security import AuthenticationError
from app.routers import auth_routes
from app.services.auth_service import AuthServiceError

logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("auth-service")

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Registration, login, JWT authentication, token verification and password change "
                "for the ShopEase platform. Use **Authorize** and paste the `access_token` from /api/auth/login.",
)
app.include_router(auth_routes.router)


def error_response(status_code: int, error: str, message: str, details: list[dict] | None = None,
                   headers: dict | None = None) -> JSONResponse:
    body = {"status_code": status_code, "error": error, "message": message}
    if details:
        body["details"] = details
    return JSONResponse(status_code=status_code, content=body, headers=headers)


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    return error_response(401, "Unauthorized", exc.message, headers={"WWW-Authenticate": "Bearer"})


@app.exception_handler(AuthServiceError)
async def service_error_handler(request: Request, exc: AuthServiceError):
    return error_response(exc.status_code, exc.error, exc.message)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    details = []
    for err in exc.errors():
        field = ".".join(str(part) for part in err["loc"] if part != "body") or "body"
        message = "Field is required" if err["type"] == "missing" else err["msg"].removeprefix("Value error, ")
        details.append({"field": field, "message": message})  # never echo the submitted values (passwords!)
    return error_response(422, "Validation Error", "Invalid request data", details)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    title = {404: "Not Found", 405: "Method Not Allowed"}.get(exc.status_code, "Error")
    return error_response(exc.status_code, title, str(exc.detail))


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.exception("Unexpected error on %s %s", request.method, request.url.path)
    return error_response(500, "Internal Server Error", "An unexpected error occurred. Please try again later.")


@app.get("/health", tags=["General"], summary="Health check")
def health():
    return {"status": "ok", "service": settings.app_name}
