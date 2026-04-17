from datetime import datetime, timedelta, timezone
import hashlib

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _normalize_password(password: str) -> str:
    """
    Hash password with SHA-256 first to avoid bcrypt 72-byte limit.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    normalized = _normalize_password(plain)
    return pwd_context.verify(normalized, hashed)


def hash_password(password: str) -> str:
    normalized = _normalize_password(password)
    return pwd_context.hash(normalized)


def create_access_token(subject: str, extra: dict | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload: dict = {"sub": subject, "exp": int(expire.timestamp())}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def parse_user_id_from_token(token: str) -> int:
    try:
        data = decode_token(token)
        sub = data.get("sub")
        if sub is None:
            raise ValueError("missing sub")
        return int(sub)
    except (JWTError, ValueError) as e:
        raise ValueError("invalid token") from e
