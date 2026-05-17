from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

try:
    from backend.dependencies import get_current_user, require_admin
    from backend.services.feature_flags import load_flags, set_flag, get_effective_flag
    from backend.models import FeatureRequest, User, get_db
except ModuleNotFoundError:
    from dependencies import get_current_user, require_admin
    from services.feature_flags import load_flags, set_flag, get_effective_flag
    from models import FeatureRequest, User, get_db

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class FeatureFlagsOut(BaseModel):
    ENABLE_SPACY: bool
    ENABLE_TRANSFORMERS: bool
    ENABLE_WHOIS: bool


class FeatureFlagsUpdate(BaseModel):
    ENABLE_SPACY: bool | None = None
    ENABLE_TRANSFORMERS: bool | None = None
    ENABLE_WHOIS: bool | None = None


class FeatureRequestSchema(BaseModel):
    feature_name: str


@router.get("/features", response_model=FeatureFlagsOut)
def get_features(user: dict = Depends(get_current_user)):
    flags = load_flags()
    return FeatureFlagsOut(
        ENABLE_SPACY=flags["ENABLE_SPACY"],
        ENABLE_TRANSFORMERS=flags["ENABLE_TRANSFORMERS"],
        ENABLE_WHOIS=flags["ENABLE_WHOIS"],
    )


@router.put("/features", response_model=FeatureFlagsOut)
def update_features(data: FeatureFlagsUpdate, user: dict = Depends(require_admin)):
    if data.ENABLE_SPACY is not None:
        set_flag("ENABLE_SPACY", data.ENABLE_SPACY)
    if data.ENABLE_TRANSFORMERS is not None:
        set_flag("ENABLE_TRANSFORMERS", data.ENABLE_TRANSFORMERS)
    if data.ENABLE_WHOIS is not None:
        set_flag("ENABLE_WHOIS", data.ENABLE_WHOIS)

    flags = load_flags()
    return FeatureFlagsOut(
        ENABLE_SPACY=flags["ENABLE_SPACY"],
        ENABLE_TRANSFORMERS=flags["ENABLE_TRANSFORMERS"],
        ENABLE_WHOIS=flags["ENABLE_WHOIS"],
    )


@router.get("/my-features", response_model=FeatureFlagsOut)
def get_my_features(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Return the effective feature flags for the currently authenticated user, including per-user overrides."""
    user = db.query(User).filter(User.email == current_user["sub"]).first()
    user_id = user.id if user else None
    
    return FeatureFlagsOut(
        ENABLE_SPACY=get_effective_flag("ENABLE_SPACY", user_id, db),
        ENABLE_TRANSFORMERS=get_effective_flag("ENABLE_TRANSFORMERS", user_id, db),
        ENABLE_WHOIS=get_effective_flag("ENABLE_WHOIS", user_id, db),
    )


@router.post("/feature-request", status_code=status.HTTP_201_CREATED)
def submit_feature_request(
    data: FeatureRequestSchema,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    feature_name = data.feature_name.strip()
    if not feature_name:
        raise HTTPException(status_code=400, detail="Feature name is required.")

    user_email = current_user["sub"]
    existing = (
        db.query(FeatureRequest)
        .filter(
            FeatureRequest.user_email == user_email,
            FeatureRequest.feature_name == feature_name,
            FeatureRequest.status == "pending",
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400,
            detail="You already have a pending request for this feature.",
        )

    new_request = FeatureRequest(
        user_email=user_email,
        feature_name=feature_name,
        status="pending",
    )
    db.add(new_request)
    db.commit()

    return {"message": "Request submitted. An admin will review it shortly."}
