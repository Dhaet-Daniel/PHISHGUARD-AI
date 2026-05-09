from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

try:
    from backend.auth import pwd_context
    from backend.models import RequestStatus, SignupRequest, User, get_db
except ModuleNotFoundError:
    from auth import pwd_context
    from models import RequestStatus, SignupRequest, User, get_db

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class SignupRequestSchema(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    organization: str | None = None


@router.post("/signup-request")
def create_signup_request(data: SignupRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="A user with this email already exists.")

    existing_request = db.query(SignupRequest).filter(SignupRequest.email == data.email).first()
    if existing_request:
        if existing_request.status == RequestStatus.PENDING:
            raise HTTPException(status_code=400, detail="A pending request with this email already exists.")
        raise HTTPException(
            status_code=400,
            detail="A sign-up request with this email already exists. Please contact an administrator.",
        )

    new_request = SignupRequest(
        full_name=data.full_name.strip(),
        email=data.email,
        organization=data.organization.strip() if data.organization else None,
        hashed_password=pwd_context.hash(data.password),
        status=RequestStatus.PENDING,
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)
    return {"message": "Sign-up request submitted successfully. Awaiting admin approval."}
