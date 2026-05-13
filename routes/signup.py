from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

try:
    from backend.auth import pwd_context
    from backend.models import RequestStatus, SignupRequest, TrustedDomain, User, UserRole, get_db
except ModuleNotFoundError:
    from auth import pwd_context
    from models import RequestStatus, SignupRequest, TrustedDomain, User, UserRole, get_db

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

    # Hash the password once
    hashed_pw = pwd_context.hash(data.password)
    
    # Extract domain from email
    domain = data.email.split("@")[-1].lower()
    
    # Check if domain is trusted
    trusted = db.query(TrustedDomain).filter(TrustedDomain.domain == domain).first()
    
    if trusted:
        # Auto-approve: create the user immediately
        new_user = User(
            email=data.email,
            hashed_password=hashed_pw,
            role=UserRole.USER
        )
        db.add(new_user)
        
        # Record the request for audit
        new_req = SignupRequest(
            full_name=data.full_name.strip(),
            email=data.email,
            organization=data.organization.strip() if data.organization else None,
            hashed_password=hashed_pw,
            status=RequestStatus.AUTO_APPROVED
        )
        db.add(new_req)
        db.commit()
        db.refresh(new_user)
        return {
            "message": "Sign-up approved automatically. You can now log in.",
            "auto_approved": True,
            "email": new_user.email
        }
    else:
        # Manual approval required
        new_request = SignupRequest(
            full_name=data.full_name.strip(),
            email=data.email,
            organization=data.organization.strip() if data.organization else None,
            hashed_password=hashed_pw,
            status=RequestStatus.PENDING,
        )
        db.add(new_request)
        db.commit()
        db.refresh(new_request)
        return {"message": "Sign-up request submitted successfully. Awaiting admin approval."}
