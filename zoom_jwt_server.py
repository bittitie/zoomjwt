"""
Zoom JWT API server

Install:  pip install fastapi uvicorn
Run:      uvicorn zoom_jwt_server:app --host 0.0.0.0 --port 8002

Environment (all required):
  ZOOM_JWT_API_KEY     clients must send this in the X-API-Key header
  ZOOM_CLIENT_ID       Zoom Client ID (used as appKey)
  ZOOM_CLIENT_SECRET   Zoom Client Secret (used to sign the token)

POST /token[?ttl_seconds=7200]   (header: X-API-Key: <key>, no body needed)
-> {"client_id": "...", "client_secret": "...", "token": "<jwt>",
    "issued_at": 1700000000, "expires_at": 1700007200}
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from fastapi import Depends, FastAPI, HTTPException, Query, Response, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} environment variable must be set")
    return value


API_KEY = _require_env("ZOOM_JWT_API_KEY")
ZOOM_CLIENT_ID = _require_env("ZOOM_CLIENT_ID")
ZOOM_CLIENT_SECRET = _require_env("ZOOM_CLIENT_SECRET")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str | None = Security(api_key_header)) -> None:
    # constant-time comparison to avoid timing attacks
    if not key or not secrets.compare_digest(key.encode(), API_KEY.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


app = FastAPI(title="Zoom JWT Generator")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_zoom_jwt(key: str, secret: str, ttl_seconds: int) -> tuple[str, int, int]:
    iat = int(time.time()) - 30  # small backdate to tolerate clock skew
    exp = iat + ttl_seconds

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64(
        json.dumps(
            {"appKey": key, "iat": iat, "exp": exp, "tokenExp": exp},
            separators=(",", ":"),
        ).encode()
    )
    signature = b64(
        hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}", iat, exp


class TokenResponse(BaseModel):
    client_id: str
    client_secret: str
    token: str
    issued_at: int
    expires_at: int


@app.post("/token", response_model=TokenResponse, dependencies=[Depends(require_api_key)])
def issue_token(
    response: Response,
    # Zoom requires exp to be between 30 minutes and 48 hours after iat
    ttl_seconds: int = Query(default=2 * 60 * 60, ge=1800, le=48 * 60 * 60),
):
    token, iat, exp = create_zoom_jwt(ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET, ttl_seconds)
    # the response contains the client secret: make sure nothing caches it
    response.headers["Cache-Control"] = "no-store"
    return TokenResponse(
        client_id=ZOOM_CLIENT_ID,
        client_secret=ZOOM_CLIENT_SECRET,
        token=token,
        issued_at=iat,
        expires_at=exp,
    )


@app.get("/health")
def health():
    return {"status": "ok"}
