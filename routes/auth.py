from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

try:
    from backend.auth import create_access_token, pwd_context
    from backend.models import User, UserRole, get_db
except ModuleNotFoundError:
    from auth import create_access_token, pwd_context
    from models import User, UserRole, get_db

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not user.hashed_password or not pwd_context.verify(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    role = user.role.value if isinstance(user.role, UserRole) else str(user.role)
    token = create_access_token({"sub": user.email, "role": role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": role,
    }
