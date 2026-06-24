from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from jose import JWTError, jwt
from pydantic import BaseModel

from shared.config.settings import get_settings


class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    role: str
    permissions: List[str] = []


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class JWTProvider:
    def __init__(self) -> None:
        self._settings = get_settings()

    def create_access_token(
        self,
        subject: str,
        role: str,
        permissions: Optional[List[str]] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> TokenResponse:
        now = datetime.now(timezone.utc)
        access_expires = now + timedelta(minutes=self._settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expires = now + timedelta(minutes=self._settings.JWT_REFRESH_TOKEN_EXPIRE_MINUTES)

        access_payload = {
            "sub": subject,
            "exp": access_expires,
            "iat": now,
            "role": role,
            "permissions": permissions or [],
            "type": "access",
            **(extra_claims or {}),
        }

        refresh_payload = {
            "sub": subject,
            "exp": refresh_expires,
            "iat": now,
            "type": "refresh",
        }

        access_token = jwt.encode(
            access_payload,
            self._settings.SECRET_KEY,
            algorithm=self._settings.JWT_ALGORITHM,
        )

        refresh_token = jwt.encode(
            refresh_payload,
            self._settings.SECRET_KEY,
            algorithm=self._settings.JWT_ALGORITHM,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self._settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    def decode_token(self, token: str) -> TokenPayload:
        try:
            payload = jwt.decode(
                token,
                self._settings.SECRET_KEY,
                algorithms=[self._settings.JWT_ALGORITHM],
            )
            return TokenPayload(
                sub=payload.get("sub", ""),
                exp=datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc),
                iat=datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc),
                role=payload.get("role", ""),
                permissions=payload.get("permissions", []),
            )
        except JWTError as e:
            raise ValueError(f"Invalid token: {e}") from e

    def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        payload = self.decode_token(refresh_token)
        if payload.exp < datetime.now(timezone.utc):
            raise ValueError("Refresh token expired")
        return self.create_access_token(
            subject=payload.sub,
            role=payload.role,
        )
