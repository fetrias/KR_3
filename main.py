import os
import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv


load_dotenv()

MODE = os.getenv("MODE", "DEV").upper()
if MODE not in {"DEV", "PROD"}:
    raise RuntimeError("MODE must be DEV or PROD")

DOCS_USER = os.getenv("DOCS_USER", "docs")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "docs")

app = FastAPI(title="KR3 Task 6", docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()
docs_security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserBase(BaseModel):
    username: str


class User(UserBase):
    password: str


class UserInDB(UserBase):
    hashed_password: str

# In-memory user store: username -> user in DB format.
fake_users_db: dict[str, UserInDB] = {}


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


@app.post("/register")
def register(user: User):
    if get_user_by_username(user.username) is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    user_in_db = UserInDB(
        username=user.username,
        hashed_password=pwd_context.hash(user.password),
    )
    fake_users_db[user.username] = user_in_db
    return {"message": "User registered successfully"}


@app.get("/login")
def login(user: UserInDB = Depends(auth_user)):
    return {"message": f"Welcome, {user.username}!"}


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
