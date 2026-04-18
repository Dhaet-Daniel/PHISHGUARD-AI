from __future__ import annotations

import asyncio
from email import policy
from email.parser import Parser
import json

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

try:
    from backend.core.limiter import limiter
    from backend.models import DetectionResult as DBResult
    from backend.models import Feedback, dumps_json, get_db
    from backend.schemas.email import (
        EmailRequest,
        EmailResponse,
        FeedbackRequest,
        StoredEmailResult,
        StoredEmailResultDetail,
        StoredEmailResultList,
        StoredFeedbackItem,
    )
    from backend.services.detector import detect_phishing
except ModuleNotFoundError:
    from core.limiter import limiter
    from models import DetectionResult as DBResult
    from models import Feedback, dumps_json, get_db
    from schemas.email import (
        EmailRequest,
        EmailResponse,
        FeedbackRequest,
        StoredEmailResult,
        StoredEmailResultDetail,
        StoredEmailResultList,
        StoredFeedbackItem,
    )
    from services.detector import detect_phishing

router = APIRouter(tags=["phishing-detection"])


def _extract_raw_email_parts(raw_email: str) -> dict:
    message = Parser(policy=policy.default).parsestr(raw_email)
    text_parts: list[str] = []
    html_parts: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                text_parts.append(part.get_content())
            elif content_type == "text/html":
                html_parts.append(part.get_content())
    else:
        content_type = message.get_content_type()
        if content_type == "text/html":
            html_parts.append(message.get_content())
        else:
            text_parts.append(message.get_content())

    headers = {key: value for key, value in message.items()}
    sender_value = message.get("From", "")
    sender_email = sender_value
    if "<" in sender_value and ">" in sender_value:
        sender_email = sender_value.split("<", 1)[1].split(">", 1)[0].strip()

    return {
        "subject": message.get("Subject"),
        "sender": sender_email or None,
        "body_text": "\n".join(part.strip() for part in text_parts if part).strip() or None,
        "body_html": "\n".join(part.strip() for part in html_parts if part).strip() or None,
        "headers": headers,
    }


def _normalize_request(email: EmailRequest) -> dict:
    raw_parts = _extract_raw_email_parts(email.raw_email) if email.raw_email else {}
    sender_email = (
        (email.sender_info.email if email.sender_info else None)
        or email.sender
        or raw_parts.get("sender")
    )
    headers = dict(raw_parts.get("headers", {}))
    headers.update(email.headers or {})
    if email.sender_info:
        if email.sender_info.reply_to:
            headers.setdefault("Reply-To", email.sender_info.reply_to)
        if email.sender_info.return_path:
            headers.setdefault("Return-Path", email.sender_info.return_path)

    body_text = email.body_text or raw_parts.get("body_text") or email.body
    body_html = email.body_html or raw_parts.get("body_html")
    combined_body = "\n\n".join(part for part in [body_text, body_html] if part)
    subject = email.subject or raw_parts.get("subject")

    explicit_links = [link.model_dump() for link in (email.links or [])]
    attachment_metadata = [attachment.model_dump() for attachment in (email.attachments or [])]

    return {
        "subject": subject,
        "sender": sender_email,
        "body_text": body_text,
        "body_html": body_html,
        "combined_body": combined_body,
        "headers": headers or None,
        "links": explicit_links,
        "attachments": attachment_metadata,
        "display_name": email.sender_info.display_name if email.sender_info else None,
    }


def _build_db_result(email: EmailRequest, result: dict) -> DBResult:
    return DBResult(
        subject=email.subject,
        sender=email.sender,
        body=email.body,
        prediction=result["prediction"],
        category=result["category"],
        confidence=result["confidence"],
        score=result["score"],
        risk_level=result["risk_level"],
        matched_keywords=dumps_json(result["matched_keywords"]),
        reason=result["reason"],
        summary=result["summary"],
        risk_signals=dumps_json(result["risk_signals"]),
        trust_signals=dumps_json(result["trust_signals"]),
        recommended_actions=dumps_json(result["recommended_actions"]),
        analysis_breakdown=dumps_json(result["analysis_breakdown"]),
        headers=dumps_json(email.headers or {}),
        attachment_metadata=dumps_json([attachment.model_dump() for attachment in (email.attachments or [])]),
    )


def _build_stored_result(record: DBResult) -> StoredEmailResult:
    return StoredEmailResult(
        record_id=record.id,
        subject=record.subject,
        sender=record.sender,
        prediction=record.prediction,
        category=record.category,
        confidence=record.confidence,
        score=record.score,
        risk_level=record.risk_level,
        summary=record.summary,
        reason=record.reason,
        matched_keywords=json.loads(record.matched_keywords or "[]"),
        created_at=record.created_at,
    )


def _load_json_field(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _build_feedback_item(feedback: Feedback) -> StoredFeedbackItem:
    return StoredFeedbackItem(
        feedback_id=feedback.id,
        email_id=feedback.email_id,
        detection_result_id=feedback.detection_result_id,
        actual_prediction=feedback.actual_prediction,
        user_feedback=feedback.user_feedback,
        matched_keywords=_load_json_field(feedback.matched_keywords, []),
        reason=feedback.reason,
        created_at=feedback.created_at,
    )


def _build_stored_result_detail(record: DBResult) -> StoredEmailResultDetail:
    feedback_items = sorted(
        record.feedback_items,
        key=lambda item: (item.created_at, item.id),
        reverse=True,
    )
    return StoredEmailResultDetail(
        record_id=record.id,
        subject=record.subject,
        sender=record.sender,
        body=record.body,
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
        headers=_load_json_field(record.headers, {}),
        attachment_metadata=_load_json_field(record.attachment_metadata, []),
        created_at=record.created_at,
        feedback=[_build_feedback_item(item) for item in feedback_items],
    )

PREDICT_REQUEST_EXAMPLES = {
    "safe_newsletter": {
        "summary": "Legitimate newsletter-style email",
        "description": "A branded informational email with strong header alignment and no coercive language.",
        "value": {
            "subject": "Host Your Own Hackathon on Kaggle Now!",
            "sender": "no-reply@kaggle.com",
            "body": (
                "Hi Daniel Kapolobwe, Community Hackathons are now available to all "
                "Kaggle users at no cost. Learn more at https://www.kaggle.com/. "
                "You can unsubscribe or update your preferences on your profile page."
            ),
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.kaggle.com by mx.google.com",
                "Reply-To": "no-reply@kaggle.com",
                "Return-Path": "<bounce@kaggle.com>",
            },
            "attachments": [],
        },
    },
    "high_risk_email": {
        "summary": "Phishing-style credential lure",
        "description": "An urgent message using a risky sender, mismatched headers, and a shortened link.",
        "value": {
            "subject": "Urgent: Verify your payroll account",
            "sender": "security-team@safe-payments-alert.com",
            "body": (
                "Your account has been suspended. Click here immediately to confirm "
                "your identity and reset your password: http://bit.ly/payroll-reset"
            ),
            "headers": {
                "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
                "Received": "from unknown-relay.example",
                "Reply-To": "support@credential-check.xyz",
                "Return-Path": "<mailer@credential-check.xyz>",
            },
            "attachments": [
                {"filename": "Payroll_Update.scr", "content_type": "application/octet-stream", "size": 34816}
            ],
        },
    },
}

BATCH_REQUEST_EXAMPLES = {
    "mixed_batch": {
        "summary": "A mixed batch with one safe email and one risky email",
        "value": [
            PREDICT_REQUEST_EXAMPLES["safe_newsletter"]["value"],
            PREDICT_REQUEST_EXAMPLES["high_risk_email"]["value"],
        ],
    }
}

PREDICT_RESPONSE_EXAMPLES = {
    200: {
        "description": "Successful phishing analysis",
        "content": {
            "application/json": {
                "example": {
                    "record_id": 42,
                    "prediction": "Safe",
                    "category": "legitimate_marketing",
                    "confidence": 0.911,
                    "score": 0.089,
                    "risk_level": "Low",
                    "matched_keywords": [],
                    "reason": "No major phishing patterns detected.",
                    "summary": "This email looks low risk because the sender uses a branded domain rather than a free mailbox provider.",
                    "risk_signals": [],
                    "trust_signals": [
                        "The sender uses a branded domain rather than a free mailbox provider.",
                        "No suspicious URLs were detected.",
                        "Authentication headers indicate SPF checks passed.",
                    ],
                    "recommended_actions": [
                        "You can review the message normally, but still verify destination domains before signing in."
                    ],
                    "analysis_breakdown": {
                        "keyword": 0.0,
                        "sender": 0.01,
                        "url": 0.0,
                        "ml": 0.0,
                        "urgency": 0.0,
                        "headers": 0.0,
                        "attachments": 0.0,
                        "alignment": 0.0,
                        "trust_credit": 0.16,
                    },
                }
            }
        },
    },
    422: {
        "description": "Validation error caused by malformed request data",
        "content": {
            "application/json": {
                "example": {
                    "detail": [
                        {
                            "loc": ["body", "sender"],
                            "msg": "String should match pattern '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$'",
                            "type": "string_pattern_mismatch",
                        }
                    ]
                }
            }
        },
    },
    500: {
        "description": "Unexpected server error",
        "content": {"application/json": {"example": {"detail": "An unexpected server error occurred."}}},
    },
}


@router.get(
    "/results/recent",
    response_model=StoredEmailResultList,
    summary="View recently stored analysis results",
    description="Lightweight admin-style endpoint for inspecting the most recent stored single and batch prediction records.",
)
@limiter.limit("30/minute")
async def recent_results(
    request: Request,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    safe_limit = max(1, min(limit, 50))
    records = (
        db.query(DBResult)
        .order_by(desc(DBResult.created_at), desc(DBResult.id))
        .limit(safe_limit)
        .all()
    )
    return StoredEmailResultList(
        count=len(records),
        results=[_build_stored_result(record) for record in records],
    )


@router.get(
    "/results/{record_id}",
    response_model=StoredEmailResultDetail,
    summary="View one stored analysis record in full detail",
    description="Admin-style endpoint for inspecting a saved analysis record together with any linked reviewer feedback.",
)
@limiter.limit("30/minute")
async def result_detail(
    request: Request,
    record_id: int,
    db: Session = Depends(get_db),
):
    record = db.query(DBResult).filter(DBResult.id == record_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return _build_stored_result_detail(record)


@router.post(
    "/predict",
    response_model=EmailResponse,
    summary="Analyze email for phishing risk",
    description=(
        "Analyze a single email using refined phishing heuristics, sender/header "
        "alignment checks, attachment metadata, and explainable next-step guidance."
    ),
    responses=PREDICT_RESPONSE_EXAMPLES,
)
@limiter.limit("30/minute")
async def predict_email(
    request: Request,
    email: EmailRequest = Body(..., openapi_examples=PREDICT_REQUEST_EXAMPLES),
    db: Session = Depends(get_db),
):
    try:
        normalized = _normalize_request(email)
        result = await detect_phishing(
            normalized["subject"],
            normalized["sender"],
            normalized["combined_body"],
            normalized["headers"],
            normalized["attachments"],
            normalized["links"],
            normalized["body_text"],
            normalized["body_html"],
        )

        db_email = email.model_copy(
            update={
                "subject": normalized["subject"],
                "sender": normalized["sender"],
                "body": normalized["combined_body"],
                "headers": normalized["headers"],
            }
        )
        db_result = _build_db_result(db_email, result)
        db.add(db_result)
        db.commit()
        db.refresh(db_result)

        return EmailResponse(record_id=db_result.id, **result)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An unexpected server error occurred.")


@router.post(
    "/batch-predict",
    response_model=list[EmailResponse],
    summary="Analyze multiple emails in one request",
    description="Submit up to 10 emails and receive one explainable phishing assessment per message.",
    responses={
        400: {
            "description": "Batch exceeded supported size",
            "content": {
                "application/json": {
                    "example": {"detail": "Batch size limited to 10 emails"}
                }
            },
        },
        422: PREDICT_RESPONSE_EXAMPLES[422],
    },
)
@limiter.limit("10/minute")
async def batch_predict_emails(
    request: Request,
    emails: list[EmailRequest] = Body(..., openapi_examples=BATCH_REQUEST_EXAMPLES),
    db: Session = Depends(get_db),
):
    if len(emails) > 10:
        raise HTTPException(status_code=400, detail="Batch size limited to 10 emails")

    try:
        normalized_emails = [_normalize_request(email) for email in emails]
        results = await asyncio.gather(
            *[
                detect_phishing(
                    normalized["subject"],
                    normalized["sender"],
                    normalized["combined_body"],
                    normalized["headers"],
                    normalized["attachments"],
                    normalized["links"],
                    normalized["body_text"],
                    normalized["body_html"],
                )
                for normalized in normalized_emails
            ]
        )

        db_results = [
            _build_db_result(
                emails[index].model_copy(
                    update={
                        "subject": normalized_emails[index]["subject"],
                        "sender": normalized_emails[index]["sender"],
                        "body": normalized_emails[index]["combined_body"],
                        "headers": normalized_emails[index]["headers"],
                    }
                ),
                result,
            )
            for index, result in enumerate(results)
        ]
        db.add_all(db_results)
        db.commit()
        for db_result in db_results:
            db.refresh(db_result)

        return [
            EmailResponse(record_id=db_result.id, **result)
            for db_result, result in zip(db_results, results, strict=False)
        ]
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An unexpected server error occurred.")


@router.post(
    "/feedback",
    summary="Submit reviewer feedback for a previous analysis",
    description="Store human feedback so the team can audit false positives and false negatives.",
)
@limiter.limit("20/minute")
async def submit_feedback(
    request: Request,
    feedback: FeedbackRequest,
    db: Session = Depends(get_db),
):
    try:
        if feedback.detection_result_id is None and not feedback.email_id:
            raise HTTPException(
                status_code=400,
                detail="Provide detection_result_id or email_id so feedback can be linked to an analysis record.",
            )

        db_feedback = Feedback(
            email_id=feedback.email_id or str(feedback.detection_result_id),
            detection_result_id=feedback.detection_result_id,
            actual_prediction=feedback.actual_prediction,
            user_feedback=feedback.user_feedback,
            matched_keywords=dumps_json(feedback.matched_keywords),
            reason=feedback.reason,
        )
        db.add(db_feedback)
        db.commit()
        db.refresh(db_feedback)
        return {"message": "Feedback submitted successfully", "feedback_id": db_feedback.id}
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An unexpected server error occurred.")
