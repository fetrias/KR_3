import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials


app = FastAPI(title="KR3 Task 6")
security = HTTPBasic()

# Minimal in-memory credentials for the base-auth task.
VALID_USERNAME = "user1"
VALID_PASSWORD = "pass1"


def check_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    is_correct_username = secrets.compare_digest(credentials.username, VALID_USERNAME)
    is_correct_password = secrets.compare_digest(credentials.password, VALID_PASSWORD)

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


@app.get("/login")
def login(_: str = Depends(check_credentials)):
    return {"message": "You got my secret, welcome"}
