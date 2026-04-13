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
from database import get_db_connection


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
    role: str = "guest"


class LoginPayload(BaseModel):
    username: str
    password: str


class RegisterPayload(BaseModel):
    username: str
    password: str
    role: str = "guest"

# In-memory user store: username -> user in DB format.
fake_users_db: dict[str, UserInDB] = {}
rate_limit_store: dict[str, list[float]] = {}

roles_permissions: dict[str, set[str]] = {
    "admin": {"create", "read", "update", "delete"},
    "user": {"read", "update"},
    "guest": {"read"},
}


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


def get_current_user_from_token(username: str = Depends(verify_jwt_token)) -> UserInDB:
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )
    return user


def require_roles(*allowed_roles: str):
    def checker(user: UserInDB = Depends(get_current_user_from_token)) -> UserInDB:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return user

    return checker


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


@app.post("/auth/register")
def register_auth(user: RegisterPayload, request: Request):
    enforce_rate_limit(request, key="register", limit=1, per_seconds=60)

    if get_user_by_username(user.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    if user.role not in roles_permissions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

    user_in_db = UserInDB(
        username=user.username,
        hashed_password=pwd_context.hash(user.password),
        role=user.role,
    )
    fake_users_db[user.username] = user_in_db
    return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "New user created"})


@app.post("/register")
def register(user: User):
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, user.password),
        )
        connection.commit()
    finally:
        connection.close()

    return {"message": "User registered successfully!"}


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
def protected_resource(_: UserInDB = Depends(require_roles("admin", "user"))):
    return {"message": "Access granted"}


@app.post("/admin/create_resource")
def admin_create_resource(_: UserInDB = Depends(require_roles("admin"))):
    return {"message": "Admin resource created"}


@app.get("/user/read_resource")
def user_read_resource(_: UserInDB = Depends(require_roles("admin", "user", "guest"))):
    return {"message": "Resource read allowed"}


@app.put("/user/update_resource")
def user_update_resource(_: UserInDB = Depends(require_roles("admin", "user"))):
    return {"message": "Resource update allowed"}


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
