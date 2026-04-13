import os
import secrets
from datetime import datetime, timedelta, timezone
import time

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv


load_dotenv()

MODE = os.getenv("MODE", "DEV").upper()
if MODE not in {"DEV", "PROD"}:
    raise RuntimeError("MODE must be DEV or PROD")

DOCS_USER = os.getenv("DOCS_USER", "docs")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "docs")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

app = FastAPI(title="KR3 Task 6", docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()
docs_security = HTTPBasic()
bearer_security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserBase(BaseModel):
    username: str


class User(UserBase):
    password: str


class UserInDB(UserBase):
    hashed_password: str


class LoginPayload(BaseModel):
    username: str
    password: str

# In-memory user store: username -> user in DB format.
fake_users_db: dict[str, UserInDB] = {}
rate_limit_store: dict[str, list[float]] = {}


def get_user_by_username(username: str) -> UserInDB | None:
    for stored_username, user in fake_users_db.items():
        if secrets.compare_digest(username, stored_username):
            return user
    return None


def auth_user(credentials: HTTPBasicCredentials = Depends(security)) -> UserInDB:
    user = get_user_by_username(credentials.username)

    is_valid_user = user is not None
    is_valid_password = is_valid_user and pwd_context.verify(
        credentials.password, user.hashed_password
    )

    if not (is_valid_user and is_valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user


def verify_docs_user(credentials: HTTPBasicCredentials = Depends(docs_security)) -> None:
    is_valid_username = secrets.compare_digest(credentials.username, DOCS_USER)
    is_valid_password = secrets.compare_digest(credentials.password, DOCS_PASSWORD)
    if not (is_valid_username and is_valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


def authenticate_user(username: str, password: str) -> bool:
    user = get_user_by_username(username)
    return user is not None and pwd_context.verify(password, user.hashed_password)


def create_access_token(subject: str) -> str:
    payload = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_security),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )

    username = payload.get("sub")
    if not isinstance(username, str) or not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )

    return username


def enforce_rate_limit(request: Request, key: str, limit: int, per_seconds: int) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket_key = f"{client_ip}:{key}"

    attempts = rate_limit_store.get(bucket_key, [])
    attempts = [ts for ts in attempts if now - ts < per_seconds]

    if len(attempts) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
        )

    attempts.append(now)
    rate_limit_store[bucket_key] = attempts


@app.post("/register")
def register(user: User, request: Request):
    enforce_rate_limit(request, key="register", limit=1, per_seconds=60)

    if get_user_by_username(user.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    user_in_db = UserInDB(
        username=user.username,
        hashed_password=pwd_context.hash(user.password),
    )
    fake_users_db[user.username] = user_in_db
    return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "New user created"})


@app.get("/login")
def login(user: UserInDB = Depends(auth_user)):
    return {"message": f"Welcome, {user.username}!"}


@app.post("/login")
def jwt_login(payload: LoginPayload, request: Request):
    enforce_rate_limit(request, key="login", limit=5, per_seconds=60)

    user = get_user_by_username(payload.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not pwd_context.verify(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed",
        )

    token = create_access_token(payload.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected_resource")
def protected_resource(_: str = Depends(verify_jwt_token)):
    return {"message": "Access granted"}


if MODE == "DEV":

    @app.get("/openapi.json", include_in_schema=False)
    def openapi_json(_: None = Depends(verify_docs_user)):
        schema = get_openapi(
            title=app.title,
            version="1.0.0",
            description="KR3 API",
            routes=app.routes,
        )
        return JSONResponse(schema)

    @app.get("/docs", include_in_schema=False)
    def docs(_: None = Depends(verify_docs_user)):
        return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} docs")
