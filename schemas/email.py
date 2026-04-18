from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SenderMetadata(BaseModel):
    email: str = Field(
        ...,
        min_length=6,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        description="Visible sender email address from the message header.",
        examples=["no-reply@kaggle.com"],
    )
    display_name: Optional[str] = Field(default=None, max_length=200, description="Optional friendly sender name.")
    reply_to: Optional[str] = Field(
        default=None,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        description="Reply-To email address when it differs from the visible sender.",
    )
    return_path: Optional[str] = Field(
        default=None,
        max_length=254,
        description="Return-Path mailbox address without angle brackets when known.",
    )


class EmailLinkInput(BaseModel):
    text: Optional[str] = Field(default=None, max_length=300, description="Visible anchor or button text.")
    url: str = Field(..., min_length=8, max_length=2048, description="Resolved destination URL.")
    source: Optional[Literal["html", "text", "button", "manual"]] = Field(
        default=None,
        description="Where the link was extracted from.",
    )


class AttachmentInput(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255, description="Original attachment filename.")
    content_type: Optional[str] = Field(default=None, description="Attachment MIME type when known.")
    size: Optional[int] = Field(default=None, ge=0, le=26214400, description="Attachment size in bytes.")
    sha256: Optional[str] = Field(default=None, min_length=32, max_length=128, description="Optional file hash.")
    is_password_protected: bool = Field(default=False, description="Whether the attachment is password protected.")
    extracted_text: Optional[str] = Field(
        default=None,
        max_length=10000,
        description="Optional OCR or text extraction result from the attachment.",
    )


class EmailRequest(BaseModel):
    subject: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=200,
        description="Email subject line exactly as received.",
        examples=["Host Your Own Hackathon on Kaggle Now!"],
    )
    sender: Optional[str] = Field(
        default=None,
        min_length=6,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        description="Legacy flat sender field. Kept for backward compatibility.",
        examples=["no-reply@kaggle.com"],
    )
    sender_info: Optional[SenderMetadata] = Field(
        default=None,
        description="Richer sender metadata including display name, reply-to, and return-path.",
    )
    body: Optional[str] = Field(
        default=None,
        min_length=10,
        max_length=10000,
        description="Legacy combined body field. Kept for backward compatibility.",
    )
    body_text: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=10000,
        description="Plain-text email body content.",
        examples=["Hi Daniel, Community Hackathons are now available to all Kaggle users."],
    )
    body_html: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=30000,
        description="HTML email body content when available.",
    )
    raw_email: Optional[str] = Field(
        default=None,
        min_length=20,
        max_length=100000,
        description="Optional full raw RFC822-style email content for parsing headers and MIME parts.",
    )
    headers: Optional[dict[str, str]] = Field(
        default=None,
        description="Optional email headers for SPF, DKIM, DMARC, routing, and sender alignment checks.",
        examples=[
            {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.kaggle.com by mx.google.com",
                "Reply-To": "no-reply@kaggle.com",
                "Return-Path": "<bounce@kaggle.com>",
            }
        ],
    )
    links: Optional[list[EmailLinkInput]] = Field(
        default=None,
        description="Explicitly extracted links from the email body or buttons.",
    )
    attachments: Optional[list[AttachmentInput]] = Field(
        default=None,
        description="Optional attachment metadata including filename, MIME type, size, and extracted text.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "subject": "Host Your Own Hackathon on Kaggle Now!",
                    "sender_info": {
                        "email": "no-reply@kaggle.com",
                        "display_name": "Kaggle",
                        "reply_to": "no-reply@kaggle.com",
                        "return_path": "bounce@kaggle.com",
                    },
                    "body_text": (
                        "Hi Daniel Kapolobwe, Community Hackathons are now available "
                        "to all Kaggle users. Learn more at https://www.kaggle.com/."
                    ),
                    "body_html": (
                        "<html><body><p>Hi Daniel Kapolobwe, Community Hackathons are now available "
                        "to all Kaggle users.</p><a href='https://www.kaggle.com/'>Learn more</a></body></html>"
                    ),
                    "headers": {
                        "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                        "Received": "from mail.kaggle.com by mx.google.com",
                        "Reply-To": "no-reply@kaggle.com",
                        "Return-Path": "<bounce@kaggle.com>",
                    },
                    "links": [
                        {"text": "Learn more", "url": "https://www.kaggle.com/", "source": "html"}
                    ],
                    "attachments": [],
                },
                {
                    "raw_email": (
                        "From: Security Team <security-team@safe-payments-alert.com>\n"
                        "Reply-To: support@credential-check.xyz\n"
                        "Return-Path: <mailer@credential-check.xyz>\n"
                        "Subject: Urgent: Verify your payroll account\n"
                        "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
                        "Content-Type: text/plain; charset=utf-8\n\n"
                        "Click here immediately to avoid account suspension. "
                        "Reset your password now at http://bit.ly/payroll-reset"
                    ),
                    "attachments": [
                        {
                            "filename": "Payroll_Update.scr",
                            "content_type": "application/octet-stream",
                            "size": 34816,
                            "is_password_protected": False
                        }
                    ],
                },
            ]
        }
    )

    @model_validator(mode="after")
    def validate_sources(self) -> "EmailRequest":
        sender_email = self.sender_info.email if self.sender_info else self.sender
        body_sources = [self.body, self.body_text, self.body_html, self.raw_email]

        if not sender_email and not self.raw_email:
            raise ValueError("Provide sender or sender_info.email, or include raw_email with parsable sender details.")
        if not any(value for value in body_sources):
            raise ValueError("Provide at least one of body, body_text, body_html, or raw_email.")
        if self.subject is None and self.raw_email is None:
            raise ValueError("Provide subject directly or include raw_email with a Subject header.")
        return self


class EmailResponse(BaseModel):
    record_id: Optional[int] = Field(default=None, description="Saved database record id for this analysis.")
    prediction: Literal["Phishing", "Safe"]
    category: Literal[
        "phishing",
        "suspicious",
        "legitimate_marketing",
        "transactional",
        "security_notice",
        "general_safe",
    ] = Field(..., description="More precise classification bucket for downstream UI and review.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the final verdict.")
    score: float = Field(..., ge=0.0, le=1.0, description="Overall phishing risk score where higher means riskier.")
    risk_level: Literal["Low", "Medium", "High"] = Field(..., description="Human-friendly interpretation of the score.")
    matched_keywords: list[str] = Field(default_factory=list, description="Detected risky keywords or rule matches.")
    reason: str = Field(..., description="Short primary explanation of the verdict.")
    summary: str = Field(..., description="Analyst-style summary suitable for UI display.")
    risk_signals: list[str] = Field(default_factory=list, description="Signals that increased phishing risk.")
    trust_signals: list[str] = Field(default_factory=list, description="Signals that supported legitimacy.")
    recommended_actions: list[str] = Field(default_factory=list, description="Practical next steps for the user.")
    analysis_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Weighted component scores used to form the overall decision.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "record_id": 42,
                    "prediction": "Safe",
                    "category": "legitimate_marketing",
                    "confidence": 0.911,
                    "score": 0.089,
                    "risk_level": "Low",
                    "matched_keywords": [],
                    "reason": "No major phishing patterns detected.",
                    "summary": (
                        "This email looks low risk because the sender uses a branded "
                        "domain and the links align with the message branding."
                    ),
                    "risk_signals": [],
                    "trust_signals": [
                        "No suspicious URLs were detected.",
                        "Authentication headers indicate SPF and DKIM checks passed.",
                        "The message includes newsletter trust markers such as unsubscribe language.",
                    ],
                    "recommended_actions": [
                        "You can review the links normally, but still verify destination domains before signing in."
                    ],
                    "analysis_breakdown": {
                        "keyword": 0.0,
                        "sender": 0.0,
                        "url": 0.0,
                        "ml": 0.0,
                        "urgency": 0.0,
                        "headers": 0.0,
                        "attachments": 0.0,
                        "alignment": 0.0,
                        "trust_credit": 0.12,
                    },
                }
            ]
        }
    )


class FeedbackRequest(BaseModel):
    email_id: Optional[str] = Field(default=None, description="Legacy identifier of the analyzed email record.")
    detection_result_id: Optional[int] = Field(default=None, description="Primary key of the saved prediction record.")
    actual_prediction: Literal["Phishing", "Safe"] = Field(..., description="Correct human-reviewed verdict.")
    user_feedback: str = Field(..., min_length=1, max_length=500, description="Reviewer notes about why the prediction was right or wrong.")
    matched_keywords: list[str] = Field(default_factory=list, description="Optional indicators the reviewer wants to preserve.")
    reason: str = Field(..., min_length=1, max_length=300, description="Concise explanation of the feedback.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detection_result_id": 42,
                "actual_prediction": "Safe",
                "user_feedback": "This was a real newsletter from Kaggle and the links resolved to kaggle.com.",
                "matched_keywords": ["newsletter_footer", "brand_match"],
                "reason": "Legitimate marketing email with consistent branding.",
            }
        }
    )


class StoredEmailResult(BaseModel):
    record_id: int = Field(..., description="Saved analysis record id.")
    subject: str
    sender: str
    prediction: Literal["Phishing", "Safe"]
    category: Literal[
        "phishing",
        "suspicious",
        "legitimate_marketing",
        "transactional",
        "security_notice",
        "general_safe",
    ]
    confidence: float = Field(..., ge=0.0, le=1.0)
    score: float = Field(..., ge=0.0, le=1.0)
    risk_level: Literal["Low", "Medium", "High"]
    summary: str
    reason: str
    matched_keywords: list[str] = Field(default_factory=list)
    created_at: datetime


class StoredEmailResultList(BaseModel):
    count: int = Field(..., ge=0, description="Number of records returned.")
    results: list[StoredEmailResult]


class StoredFeedbackItem(BaseModel):
    feedback_id: int = Field(..., description="Saved feedback record id.")
    email_id: Optional[str] = Field(default=None, description="Legacy linked email identifier.")
    detection_result_id: Optional[int] = Field(default=None, description="Linked analysis record id.")
    actual_prediction: Literal["Phishing", "Safe"]
    user_feedback: str
    matched_keywords: list[str] = Field(default_factory=list)
    reason: str
    created_at: datetime


class StoredEmailResultDetail(BaseModel):
    record_id: int = Field(..., description="Saved analysis record id.")
    subject: str
    sender: str
    body: str
    prediction: Literal["Phishing", "Safe"]
    category: Literal[
        "phishing",
        "suspicious",
        "legitimate_marketing",
        "transactional",
        "security_notice",
        "general_safe",
    ]
    confidence: float = Field(..., ge=0.0, le=1.0)
    score: float = Field(..., ge=0.0, le=1.0)
    risk_level: Literal["Low", "Medium", "High"]
    matched_keywords: list[str] = Field(default_factory=list)
    reason: str
    summary: str
    risk_signals: list[str] = Field(default_factory=list)
    trust_signals: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    analysis_breakdown: dict[str, float] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    attachment_metadata: list[dict] = Field(default_factory=list)
    created_at: datetime
    feedback: list[StoredFeedbackItem] = Field(
        default_factory=list,
        description="Reviewer feedback records linked to this analysis.",
    )
