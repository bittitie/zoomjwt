"""
Zoom JWT API server

Install:  pip install fastapi uvicorn
Run:      uvicorn zoom_jwt_server:app --host 0.0.0.0 --port 8002

POST /token
  {"client_id": "...", "client_secret": "...", "ttl_seconds": 7200}   # ttl optional
-> {"token": "<jwt>", "issued_at": 1700000000, "expires_at": 1700007200}
"""
import base64
import hashlib
import hmac
import json
import time

from fastapi import FastAPI
from pydantic import BaseModel, Field

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


class TokenRequest(BaseModel):
    client_id: str = Field(min_length=1)
    client_secret: str = Field(min_length=1)
    # Zoom requires exp to be between 30 minutes and 48 hours after iat
    ttl_seconds: int = Field(default=2 * 60 * 60, ge=1800, le=48 * 60 * 60)


class TokenResponse(BaseModel):
    token: str
    issued_at: int
    expires_at: int


@app.post("/token", response_model=TokenResponse)
def issue_token(req: TokenRequest):
    token, iat, exp = create_zoom_jwt(req.client_id, req.client_secret, req.ttl_seconds)
    return TokenResponse(token=token, issued_at=iat, expires_at=exp)


@app.get("/health")
def health():
    return {"status": "ok"}
