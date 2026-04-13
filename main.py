import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel


app = FastAPI(title="KR3 Task 6")
security = HTTPBasic()
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
