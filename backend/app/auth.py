import bcrypt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, Request, Header
from fastapi.responses import Response
from jose import JWTError, jwt
from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SECURE_COOKIES
from app.database import get_db

COOKIE_NAME = "soc_token"
MAX_BCRYPT_BYTES = 72


def hash_password(password: str) -> str:
    raw = password.encode("utf-8")
    if len(raw) > MAX_BCRYPT_BYTES:
        raise HTTPException(status_code=400, detail="Password must be at most 72 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    raw = plain.encode("utf-8")
    if len(raw) > MAX_BCRYPT_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_agent_token(agent_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    payload = {"sub": str(agent_id), "scope": "agent", "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def clear_token_cookie(response: Response):
    # Flags must mirror set_token_cookie or browsers keep the old cookie.
    response.delete_cookie(key=COOKIE_NAME, path="/", samesite="lax", secure=SECURE_COOKIES)


def set_token_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


def get_current_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") == "agent":
            raise HTTPException(status_code=401, detail="Invalid token")
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(sub)
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if int(payload.get("tv", 0)) != int(user.get("token_version", 0)):
        raise HTTPException(status_code=401, detail="Session expired, please log in again")
    return user


def get_current_agent(authorization: str = Header(default=""), db=Depends(get_db)):
    token = authorization
    if token.startswith("Bearer "):
        token = token[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "agent":
            raise HTTPException(status_code=403, detail="Invalid token scope")
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        agent_id = int(sub)
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid agent token")
    agent = db.agent_keys.find_one({"id": agent_id})
    if not agent or agent.get("status") == "revoked":
        raise HTTPException(status_code=401, detail="Agent not found or revoked")
    return agent
