from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from app.database import get_db, get_next_id
from app.auth import hash_password, verify_password, create_access_token, set_token_cookie, clear_token_cookie, get_current_user
from app.models.user import UserCreate, UserLogin, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


class ProfileUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=72)
    new_password: str = Field(min_length=6, max_length=72)


@router.post("/register", summary="Create a user account")
def register(body: UserCreate, response: Response, db=Depends(get_db)):
    email = body.email.strip().lower()
    name = body.name.strip()
    if "@" not in email or "." not in email.split("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address")
    if not name:
        raise HTTPException(status_code=400, detail="Name must not be empty")
    existing = db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    now = datetime.now(timezone.utc)
    user = {
        "id": get_next_id("users"),
        "email": email,
        "hashed_password": hash_password(body.password),
        "name": name,
        "token_version": 0,
        "created_at": now,
    }
    db.users.insert_one(user)
    token = create_access_token({"sub": str(user["id"]), "tv": 0})
    set_token_cookie(response, token)
    return {"token": token, "user": UserResponse(id=user["id"], email=user["email"], name=user["name"], created_at=user["created_at"])}


@router.post("/login", summary="Log in with email + password")
def login(body: UserLogin, response: Response, db=Depends(get_db)):
    """Authenticate and set the session cookie; returns a bearer token too."""
    user = db.users.find_one({"email": body.email.strip().lower()})
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user["id"]), "tv": int(user.get("token_version", 0))})
    set_token_cookie(response, token)
    return {"token": token, "message": "Logged in"}


@router.post("/logout", summary="Log out (clears session cookie)")
def logout(response: Response):
    clear_token_cookie(response)
    return {"message": "Logged out"}


@router.get("/me", summary="Get the current user's profile")
def me(user=Depends(get_current_user)):
    return UserResponse(
        id=user["id"], email=user["email"], name=user["name"],
        created_at=user["created_at"],
        current_project_id=user.get("current_project_id"),
    )


@router.patch("/me", summary="Update the current user's display name")
def update_me(body: ProfileUpdate, user=Depends(get_current_user), db=Depends(get_db)):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name must not be empty")
    db.users.update_one({"id": user["id"]}, {"$set": {"name": name}})
    refreshed = db.users.find_one({"id": user["id"]})
    return UserResponse(
        id=refreshed["id"], email=refreshed["email"], name=refreshed["name"],
        created_at=refreshed["created_at"],
        current_project_id=refreshed.get("current_project_id"),
    )


@router.post("/change-password", summary="Change the current user's password")
def change_password(body: PasswordChange, response: Response, user=Depends(get_current_user), db=Depends(get_db)):
    doc = db.users.find_one({"id": user["id"]})
    if not doc or not verify_password(body.current_password, doc["hashed_password"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    next_tv = int(doc.get("token_version", 0)) + 1
    db.users.update_one(
        {"id": user["id"]},
        {"$set": {"hashed_password": hash_password(body.new_password), "token_version": next_tv}},
    )
    new_token = create_access_token({"sub": str(user["id"]), "tv": next_tv})
    set_token_cookie(response, new_token)
    return {"message": "Password changed", "token": new_token}
