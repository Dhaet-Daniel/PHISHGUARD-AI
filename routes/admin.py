from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.orm import Session

try:
    from backend.auth import pwd_context
    from backend.dependencies import require_admin
    from backend.models import (
        DetectionResult,
        Feedback,
        RequestStatus,
        SignupRequest,
        TrustedDomain,
        User,
        UserRole,
        get_db,
    )
    import backend.schemas.email as email_schemas
except ModuleNotFoundError:
    from auth import pwd_context
    from dependencies import require_admin
    from models import DetectionResult, Feedback, RequestStatus, SignupRequest, TrustedDomain, User, UserRole, get_db
    import schemas.email as email_schemas

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


def _load_json_field(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _to_email_response(record: DetectionResult) -> email_schemas.EmailResponse:
    return email_schemas.EmailResponse(
        record_id=record.id,
        prediction=record.prediction,
        category=record.category,
        confidence=record.confidence,
        score=record.score,
        risk_level=record.risk_level,
        matched_keywords=_load_json_field(record.matched_keywords, []),
        reason=record.reason,
        summary=record.summary,
        risk_signals=_load_json_field(record.risk_signals, []),
        trust_signals=_load_json_field(record.trust_signals, []),
        recommended_actions=_load_json_field(record.recommended_actions, []),
        analysis_breakdown=_load_json_field(record.analysis_breakdown, {}),
    )


class UserOut(BaseModel):
    id: int
    email: str
    role: UserRole

    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.USER


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    role: UserRole | None = None


class FeedbackOut(BaseModel):
    id: int
    result_id: int | None = None
    email_id: str | None = None
    actual_prediction: str | None = None
    user_feedback: str | None = None
    admin_response: str | None = None
    status: str
    reason: str | None = None
    created_at: datetime


class FeedbackUpdate(BaseModel):
    admin_response: str | None = None
    status: Literal["open", "resolved"] | None = None


class SignupRequestOut(BaseModel):
    id: int
    full_name: str
    email: str
    organization: str | None = None
    status: RequestStatus
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DomainCreate(BaseModel):
    domain: str


class DomainOut(BaseModel):
    id: int
    domain: str

    model_config = ConfigDict(from_attributes=True)


class BulkApprove(BaseModel):
    request_ids: list[int]


def _to_feedback_out(feedback: Feedback) -> FeedbackOut:
    return FeedbackOut(
        id=feedback.id,
        result_id=feedback.detection_result_id,
        email_id=feedback.email_id,
        actual_prediction=feedback.actual_prediction,
        user_feedback=feedback.user_feedback,
        admin_response=feedback.admin_response,
        status=feedback.status or "open",
        reason=feedback.reason,
        created_at=feedback.created_at,
    )


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=data.email,
        hashed_password=pwd_context.hash(data.password),
        role=data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if data.email is not None:
        duplicate = db.query(User).filter(User.email == data.email, User.id != user_id).first()
        if duplicate:
            raise HTTPException(status_code=400, detail="Email already registered")
        user.email = data.email
    if data.password is not None:
        user.hashed_password = pwd_context.hash(data.password)
    if data.role is not None:
        user.role = data.role

    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/results", response_model=list[email_schemas.EmailResponse])
def list_results(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    records = (
        db.query(DetectionResult)
        .order_by(DetectionResult.created_at.desc(), DetectionResult.id.desc())
        .offset(max(skip, 0))
        .limit(max(1, min(limit, 100)))
        .all()
    )
    return [_to_email_response(record) for record in records]


@router.delete("/results/{result_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_result(result_id: int, db: Session = Depends(get_db)):
    result = db.get(DetectionResult, result_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")

    for feedback in result.feedback_items:
        feedback.detection_result_id = None
    db.delete(result)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/feedback", response_model=list[FeedbackOut])
def list_feedback(db: Session = Depends(get_db)):
    feedback_items = db.query(Feedback).order_by(Feedback.created_at.desc(), Feedback.id.desc()).all()
    return [_to_feedback_out(item) for item in feedback_items]


@router.put("/feedback/{feedback_id}", response_model=FeedbackOut)
def update_feedback(feedback_id: int, data: FeedbackUpdate, db: Session = Depends(get_db)):
    feedback = db.get(Feedback, feedback_id)
    if feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")

    if data.admin_response is not None:
        feedback.admin_response = data.admin_response
    if data.status is not None:
        feedback.status = data.status

    db.commit()
    db.refresh(feedback)
    return _to_feedback_out(feedback)


@router.delete("/feedback/{feedback_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_feedback(feedback_id: int, db: Session = Depends(get_db)):
    feedback = db.get(Feedback, feedback_id)
    if feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")

    db.delete(feedback)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/stats")
def admin_stats(db: Session = Depends(get_db)):
    return {
        "total_users": db.query(User).count(),
        "total_scans": db.query(DetectionResult).count(),
        "open_feedback": db.query(Feedback).filter(Feedback.status == "open").count(),
    }


@router.get("/signup-requests", response_model=list[SignupRequestOut])
def list_signup_requests(
    status: RequestStatus | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(SignupRequest)
    if status is not None:
        query = query.filter(SignupRequest.status == status)
    return query.order_by(SignupRequest.created_at.desc(), SignupRequest.id.desc()).all()


@router.put("/signup-requests/{request_id}/approve")
def approve_request(request_id: int, db: Session = Depends(get_db)):
    signup_request = db.get(SignupRequest, request_id)
    if signup_request is None:
        raise HTTPException(status_code=404, detail="Request not found")
    if signup_request.status != RequestStatus.PENDING:
        raise HTTPException(status_code=400, detail="Request is not pending")
    if db.query(User).filter(User.email == signup_request.email).first():
        raise HTTPException(status_code=400, detail="A user with this email already exists.")

    new_user = User(
        email=signup_request.email,
        hashed_password=signup_request.hashed_password,
        role=UserRole.USER,
    )
    db.add(new_user)
    signup_request.status = RequestStatus.APPROVED
    db.commit()
    db.refresh(signup_request)
    return {"message": f"User {new_user.email} approved and created."}


@router.put("/signup-requests/{request_id}/reject")
def reject_request(request_id: int, db: Session = Depends(get_db)):
    signup_request = db.get(SignupRequest, request_id)
    if signup_request is None:
        raise HTTPException(status_code=404, detail="Request not found")
    if signup_request.status != RequestStatus.PENDING:
        raise HTTPException(status_code=400, detail="Request is not pending")

    signup_request.status = RequestStatus.REJECTED
    db.commit()
    return {"message": "Request rejected."}


@router.get("/trusted-domains", response_model=list[DomainOut])
def list_trusted_domains(db: Session = Depends(get_db)):
    return db.query(TrustedDomain).order_by(TrustedDomain.domain.asc()).all()


@router.post("/trusted-domains", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
def add_trusted_domain(data: DomainCreate, db: Session = Depends(get_db)):
    domain = data.domain.lower().strip()
    if db.query(TrustedDomain).filter(TrustedDomain.domain == domain).first():
        raise HTTPException(status_code=400, detail="Domain already trusted")
    new_domain = TrustedDomain(domain=domain)
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)
    return new_domain


@router.delete("/trusted-domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_trusted_domain(domain_id: int, db: Session = Depends(get_db)):
    domain = db.query(TrustedDomain).get(domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/signup-requests/bulk-approve")
def bulk_approve_requests(data: BulkApprove, db: Session = Depends(get_db)):
    approved_count = 0
    for req_id in data.request_ids:
        signup_req = db.query(SignupRequest).get(req_id)
        if not signup_req or signup_req.status != RequestStatus.PENDING:
            continue
        new_user = User(
            email=signup_req.email,
            hashed_password=signup_req.hashed_password,
            role=UserRole.USER
        )
        db.add(new_user)
        signup_req.status = RequestStatus.APPROVED
        approved_count += 1
    db.commit()
    return {"message": f"{approved_count} request(s) approved."}
