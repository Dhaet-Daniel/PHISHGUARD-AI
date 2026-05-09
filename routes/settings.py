from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

try:
    from backend.dependencies import get_current_user, require_admin
    from backend.services.feature_flags import load_flags, set_flag
except ModuleNotFoundError:
    from dependencies import get_current_user, require_admin
    from services.feature_flags import load_flags, set_flag

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class FeatureFlagsOut(BaseModel):
    ENABLE_SPACY: bool
    ENABLE_TRANSFORMERS: bool
    ENABLE_WHOIS: bool


class FeatureFlagsUpdate(BaseModel):
    ENABLE_SPACY: bool | None = None
    ENABLE_TRANSFORMERS: bool | None = None
    ENABLE_WHOIS: bool | None = None


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
