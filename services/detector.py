from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime
from functools import lru_cache
from ipaddress import ip_address
from typing import Any, TypedDict
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
import whois

logger = logging.getLogger(__name__)
nlp = None
classifier = None
_nlp_load_attempted = False
_classifier_load_attempted = False
ENABLE_SPACY = os.getenv("PHISHGUARD_ENABLE_SPACY", "").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_TRANSFORMERS = os.getenv("PHISHGUARD_ENABLE_TRANSFORMERS", "").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_WHOIS = os.getenv("PHISHGUARD_ENABLE_WHOIS", "").strip().lower() in {"1", "true", "yes", "on"}

SUSPICIOUS_KEYWORD_WEIGHTS = {
    "urgent": 0.16,
    "verify": 0.18,
    "click here": 0.22,
    "password": 0.18,
    "bank": 0.14,
    "account suspended": 0.28,
    "confirm identity": 0.2,
    "update billing": 0.22,
    "security alert": 0.18,
    "login required": 0.21,
    "reset password": 0.22,
    "account verification": 0.24,
    "suspicious activity": 0.18,
    "limited time": 0.16,
    "act now": 0.18,
    "wire transfer": 0.28,
    "gift card": 0.24,
    "invoice attached": 0.18,
}

HIGH_RISK_PHRASES = {
    "confirm identity",
    "reset password",
    "account suspended",
    "wire transfer",
    "gift card",
    "login required",
    "account verification",
}

LOW_SIGNAL_SENDER_MARKERS = {
    "no-reply": 0.01,
    "notification": 0.01,
}

HIGH_SIGNAL_SENDER_MARKERS = {
    "security": 0.04,
    "billing": 0.05,
    "payroll": 0.05,
    "admin": 0.03,
}

PHISHING_THRESHOLD = 0.58
SUSPICIOUS_THRESHOLD = 0.35
FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}
PUBLIC_SUFFIX_OVERRIDES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "co.za",
}
KNOWN_BRAND_DOMAINS = {
    "microsoft.com",
    "google.com",
    "github.com",
    "kaggle.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
}
SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly",
    r"tinyurl\.com",
    r"goo\.gl",
    r"t\.co",
    r"\.tk$",
    r"\.ml$",
    r"\.ga$",
    r"\.cf$",
    r"secure-login",
    r"verify-account",
]
MARKETING_TRUST_PATTERNS = {
    "unsubscribe": "The message includes unsubscribe language common in legitimate newsletters.",
    "preferences": "The message references email preferences, which is common in legitimate subscription mail.",
    "profile page": "The sender references account preferences instead of demanding urgent action.",
    "view in browser": "The message includes newsletter-style web viewing language.",
}
TRANSACTIONAL_TRUST_PATTERNS = {
    "receipt": "The email contains receipt-style language that often appears in transactional mail.",
    "invoice": "The email appears to discuss a transaction rather than an account reset demand.",
    "order": "The email uses order-related language common in transactional updates.",
    "ticket": "The email references a support ticket, which is common in service follow-ups.",
    "service report": "The email looks like a post-support follow-up rather than a credential lure.",
}


class DetectionResult(TypedDict):
    prediction: str
    category: str
    confidence: float
    score: float
    risk_level: str
    matched_keywords: list[str]
    reason: str
    summary: str
    risk_signals: list[str]
    trust_signals: list[str]
    recommended_actions: list[str]
    analysis_breakdown: dict[str, float]


def _get_nlp():
    global nlp, _nlp_load_attempted
    if _nlp_load_attempted:
        return nlp
    _nlp_load_attempted = True
    if not ENABLE_SPACY:
        logger.info("spaCy lemmatization is disabled. Set PHISHGUARD_ENABLE_SPACY=1 to enable it.")
        return None
    try:
        import spacy

        nlp = spacy.load("en_core_web_sm")
    except Exception as exc:  # pragma: no cover
        logger.warning("spaCy is unavailable; continuing without lemmatization: %s", exc)
        nlp = None
    return nlp


def _get_classifier():
    global classifier, _classifier_load_attempted
    if _classifier_load_attempted:
        return classifier
    _classifier_load_attempted = True
    if not ENABLE_TRANSFORMERS:
        logger.info("Transformer phishing model is disabled. Set PHISHGUARD_ENABLE_TRANSFORMERS=1 to enable it.")
        return None
    try:
        from transformers import pipeline

        classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    except Exception as exc:  # pragma: no cover
        logger.warning("Transformers pipeline is unavailable; continuing without ML scoring: %s", exc)
        classifier = None
    return classifier


def _normalize_text(*parts: str) -> str:
    return " ".join(part.strip() for part in parts if part).lower()


def _preprocess_text(text: str) -> str:
    current_nlp = _get_nlp()
    if current_nlp:
        doc = current_nlp(text.lower())
        return " ".join(token.lemma_ for token in doc if not token.is_stop and token.is_alpha)
    return text.lower()


def _extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', text)


def _extract_html_links(body: str) -> list[tuple[str, str]]:
    if "<a" not in body.lower():
        return []
    soup = BeautifulSoup(body, "html.parser")
    links: list[tuple[str, str]] = []
    for anchor in soup.find_all("a", href=True):
        links.append((anchor.get_text(" ", strip=True), anchor["href"]))
    return links


def _sender_domain(sender: str) -> str:
    return sender.rsplit("@", 1)[-1].strip().lower() if "@" in sender else ""


def _base_domain(hostname: str) -> str:
    host = hostname.lower().strip(".")
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    candidate = ".".join(parts[-2:])
    override = ".".join(parts[-3:])
    if candidate in PUBLIC_SUFFIX_OVERRIDES:
        return override
    if ".".join(parts[-2:]) in PUBLIC_SUFFIX_OVERRIDES:
        return override
    suffix = ".".join(parts[-2:])
    if suffix in PUBLIC_SUFFIX_OVERRIDES:
        return override
    if ".".join(parts[-2:]) == "co.uk":
        return override
    return ".".join(parts[-2:])


def _looks_like_ip(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_suspicious_url(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    if _looks_like_ip(domain.split(":")[0]):
        return True
    if "xn--" in domain:
        return True
    if domain.count("-") >= 3:
        return True
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, domain):
            return True
    return False


@lru_cache(maxsize=256)
def _domain_age_score(url: str) -> float:
    if not ENABLE_WHOIS:
        return 0.0
    try:
        domain = urlparse(url).netloc.split(":")[0]
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 14:
                return 0.14
            if age_days < 45:
                return 0.08
        return 0.0
    except Exception:
        return 0.0


def _parse_email_body(body: str) -> str:
    if "<html" in body.lower():
        soup = BeautifulSoup(body, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    return body


def _keyword_analysis(text: str) -> tuple[float, list[str]]:
    matched = [keyword for keyword in SUSPICIOUS_KEYWORD_WEIGHTS if keyword in text]
    score = sum(SUSPICIOUS_KEYWORD_WEIGHTS[keyword] for keyword in matched)
    return score, matched


def _sender_analysis(sender: str) -> tuple[float, list[str]]:
    matches: list[str] = []
    score = 0.0
    for marker, weight in LOW_SIGNAL_SENDER_MARKERS.items():
        if marker in sender:
            matches.append(marker)
            score += weight
    for marker, weight in HIGH_SIGNAL_SENDER_MARKERS.items():
        if marker in sender:
            matches.append(marker)
            score += weight
    return score, matches


def _url_analysis(
    sender: str,
    body: str,
    explicit_links: list[dict[str, Any]] | None = None,
    body_html: str | None = None,
) -> tuple[float, list[str], list[str], list[str], list[str]]:
    urls = _extract_urls(body)
    html_links = _extract_html_links(body_html or body)
    if explicit_links:
        for link in explicit_links:
            url = link.get("url")
            text = link.get("text") or ""
            if url:
                urls.append(url)
                html_links.append((text, url))
    urls = list(dict.fromkeys(urls))
    suspicious_urls: list[str] = []
    young_domains: list[str] = []
    trust_signals: list[str] = []
    issues: list[str] = []
    score = 0.0

    sender_base = _base_domain(_sender_domain(sender)) if _sender_domain(sender) else ""
    linked_domains = set()

    for url in urls:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()
        base = _base_domain(host) if host else ""
        if base:
            linked_domains.add(base)
        if _is_suspicious_url(url):
            suspicious_urls.append(url)
            score += 0.14
        age_score = _domain_age_score(url)
        if age_score > 0:
            young_domains.append(url)
            score += age_score
        if parsed.scheme != "https":
            issues.append(f"Link uses non-HTTPS transport: {url}.")
            score += 0.06
        query = parse_qs(parsed.query)
        if any(key.lower() in {"redirect", "url", "target"} for key in query):
            issues.append(f"Link contains redirect-style query parameters: {url}.")
            score += 0.05
        if sender_base and base and sender_base != base:
            if base in KNOWN_BRAND_DOMAINS and sender_base not in KNOWN_BRAND_DOMAINS:
                issues.append(f"Link domain {base} does not align with sender domain {sender_base}.")
                score += 0.07

    for anchor_text, href in html_links:
        visible = anchor_text.lower().strip()
        href_host = urlparse(href).netloc.lower()
        if visible.startswith("http") and href_host and _base_domain(urlparse(visible).netloc.lower()) != _base_domain(href_host):
            issues.append("HTML anchor text and actual destination do not match.")
            score += 0.1

    if urls and not suspicious_urls and sender_base and linked_domains and linked_domains == {sender_base}:
        trust_signals.append("Visible links align with the sender's base domain.")
    elif urls and not suspicious_urls and linked_domains:
        trust_signals.append("Links do not match known suspicious patterns.")

    return min(score, 0.45), suspicious_urls, young_domains, issues, trust_signals


def _ml_phishing_score(text: str) -> float:
    current_classifier = _get_classifier()
    if current_classifier is None:
        return 0.0
    try:
        result = current_classifier(text, candidate_labels=["phishing", "safe", "newsletter"])
        if "phishing" in result["labels"]:
            return result["scores"][result["labels"].index("phishing")]
    except Exception:
        return 0.0
    return 0.0


def _urgency_analysis(text: str) -> tuple[float, list[str]]:
    exclamation_count = text.count("!")
    caps_ratio = sum(1 for char in text if char.isupper()) / len(text) if text else 0
    urgent_patterns = [
        "urgent",
        "immediately",
        "within 24 hours",
        "act now",
        "final notice",
        "suspended",
        "verify now",
        "reset now",
    ]
    matched = [phrase for phrase in urgent_patterns if phrase in text.lower()]
    score = min(exclamation_count * 0.04 + caps_ratio * 0.12 + len(matched) * 0.05, 0.22)
    notes: list[str] = []
    if matched:
        notes.append(f"Urgency language detected: {', '.join(matched)}.")
    if exclamation_count >= 3:
        notes.append("Multiple exclamation marks increase pressure on the recipient.")
    if caps_ratio > 0.22:
        notes.append("Heavy capitalization suggests a pressure-based tone.")
    return score, notes


def _brand_alignment_score(sender: str, body_text: str, headers: dict[str, str] | None) -> tuple[float, list[str], list[str]]:
    sender_base = _base_domain(_sender_domain(sender)) if _sender_domain(sender) else ""
    trust_signals: list[str] = []
    issues: list[str] = []
    score = 0.0

    reply_to = (headers or {}).get("Reply-To", "")
    return_path = (headers or {}).get("Return-Path", "").strip("<>")
    reply_base = _base_domain(_sender_domain(reply_to)) if "@" in reply_to else ""
    return_base = _base_domain(_sender_domain(return_path)) if "@" in return_path else ""

    if reply_base and sender_base and reply_base != sender_base:
        issues.append("Reply-To domain does not align with the visible sender domain.")
        score += 0.12
    elif reply_base and sender_base and reply_base == sender_base:
        trust_signals.append("Reply-To aligns with the sender domain.")

    if return_base and sender_base and return_base != sender_base:
        issues.append("Return-Path domain does not align with the visible sender domain.")
        score += 0.08
    elif return_base and sender_base and return_base == sender_base:
        trust_signals.append("Return-Path aligns with the sender domain.")

    if sender_base and sender_base in body_text.lower():
        trust_signals.append("The email body references the sender's domain directly.")

    return score, issues, trust_signals


def _header_analysis(sender: str, headers: dict[str, str] | None) -> tuple[float, list[str], list[str]]:
    if not headers:
        return 0.0, [], []

    auth_text = headers.get("Authentication-Results", "").lower()
    received_text = headers.get("Received", "").lower()
    sender_domain = _base_domain(_sender_domain(sender)) if _sender_domain(sender) else ""
    issues: list[str] = []
    trust_signals: list[str] = []
    score = 0.0

    if "spf=pass" in auth_text or "spf pass" in auth_text:
        trust_signals.append("Authentication headers indicate SPF checks passed.")
    elif "spf=fail" in auth_text or "spf fail" in auth_text:
        issues.append("SPF failed for the supplied message headers.")
        score += 0.12

    if "dkim=pass" in auth_text or "dkim pass" in auth_text:
        trust_signals.append("Authentication headers indicate DKIM checks passed.")
    elif "dkim=fail" in auth_text or "dkim fail" in auth_text:
        issues.append("DKIM failed for the supplied message headers.")
        score += 0.12

    if "dmarc=pass" in auth_text or "dmarc pass" in auth_text:
        trust_signals.append("DMARC alignment appears to have passed.")
    elif "dmarc=fail" in auth_text or "dmarc fail" in auth_text:
        issues.append("DMARC alignment appears to have failed.")
        score += 0.1

    if not auth_text:
        issues.append("Authentication-Results header was not supplied, so sender validation is limited.")
        score += 0.04

    if received_text:
        if "unknown" in received_text or "localhost" in received_text:
            issues.append("Received headers suggest an unknown or local relay path.")
            score += 0.05
        elif sender_domain and sender_domain.split(".")[0] in received_text:
            trust_signals.append("Received headers point to a named mail relay chain.")

    return score, issues, trust_signals


def _marketing_trust_signals(text: str) -> list[str]:
    lower_text = text.lower()
    signals: list[str] = []
    for pattern, message in MARKETING_TRUST_PATTERNS.items():
        if pattern in lower_text:
            signals.append(message)
    return signals


def _transactional_trust_signals(text: str) -> list[str]:
    lower_text = text.lower()
    signals: list[str] = []
    for pattern, message in TRANSACTIONAL_TRUST_PATTERNS.items():
        if pattern in lower_text:
            signals.append(message)
    return signals


def _attachment_analysis(attachments: list[dict[str, Any]] | None) -> tuple[float, list[str], list[str]]:
    if not attachments:
        return 0.0, [], []

    risk_signals: list[str] = []
    trust_signals: list[str] = []
    score = 0.0
    risky_extensions = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".msi", ".hta"}
    caution_extensions = {".zip", ".rar", ".7z", ".docm", ".xlsm", ".iso"}

    for attachment in attachments:
        filename = str(attachment.get("filename", "")).lower()
        content_type = str(attachment.get("content_type", "")).lower()
        size = attachment.get("size")

        if not filename:
            continue
        if any(filename.endswith(ext) for ext in risky_extensions):
            risk_signals.append(f"Attachment filename uses a high-risk executable extension: {filename}.")
            score += 0.2
        elif any(filename.endswith(ext) for ext in caution_extensions):
            risk_signals.append(f"Attachment filename uses an extension that deserves extra caution: {filename}.")
            score += 0.08
        elif filename.endswith((".pdf", ".png", ".jpg", ".jpeg")):
            trust_signals.append(f"Attachment filename looks ordinary for document sharing: {filename}.")

        if re.search(r"\.(pdf|doc|xls|jpg|png)\.(exe|scr|js|bat)$", filename):
            risk_signals.append(f"Attachment filename appears to use a double-extension disguise: {filename}.")
            score += 0.12

        if content_type and "octet-stream" not in content_type and filename.endswith(".pdf") and "pdf" in content_type:
            trust_signals.append(f"Attachment content type is consistent with the filename for {filename}.")

        if isinstance(size, int) and size > 15_000_000:
            risk_signals.append(f"Attachment is unusually large for a typical notification email: {filename}.")
            score += 0.03

    return min(score, 0.3), risk_signals, trust_signals


def _classify_risk_level(score: float) -> str:
    if score >= 0.75:
        return "High"
    if score >= 0.35:
        return "Medium"
    return "Low"


def _classify_category(
    prediction: str,
    subject: str,
    body_text: str,
    score: float,
    trust_signals: list[str],
    risk_signals: list[str],
    header_issues: list[str],
) -> str:
    lower_text = f"{subject} {body_text}".lower()
    if prediction == "Phishing":
        return "phishing"
    if prediction == "Safe" and score >= 0.15 and (risk_signals or header_issues):
        return "suspicious"
    if prediction == "Safe" and _transactional_trust_signals(lower_text):
        return "transactional"
    if prediction == "Safe" and (
        "security alert" in lower_text
        or "new sign-in" in lower_text
        or "new login" in lower_text
        or "security activity" in lower_text
    ):
        return "security_notice"
    if prediction == "Safe" and _marketing_trust_signals(lower_text):
        return "legitimate_marketing"
    if prediction == "Safe" and (risk_signals or header_issues):
        return "suspicious"
    return "general_safe"


def _build_trust_signals(
    sender: str,
    keyword_matches: list[str],
    suspicious_urls: list[str],
    urgency_score: float,
    header_trust_signals: list[str],
    marketing_signals: list[str],
    transactional_signals: list[str],
    link_alignment_signals: list[str],
    brand_alignment_trust: list[str],
    attachment_trust: list[str],
) -> list[str]:
    trust_signals: list[str] = []
    sender_domain = _sender_domain(sender)
    if sender_domain and sender_domain not in FREE_EMAIL_DOMAINS:
        trust_signals.append("The sender uses a branded domain rather than a free mailbox provider.")
    if not keyword_matches:
        trust_signals.append("No high-risk phishing keywords were detected.")
    if not suspicious_urls:
        trust_signals.append("No suspicious URLs were detected.")
    if urgency_score < 0.05:
        trust_signals.append("The message uses a low-pressure, informational tone.")
    trust_signals.extend(header_trust_signals)
    trust_signals.extend(marketing_signals)
    trust_signals.extend(transactional_signals)
    trust_signals.extend(link_alignment_signals)
    trust_signals.extend(brand_alignment_trust)
    trust_signals.extend(attachment_trust)
    deduped: list[str] = []
    for signal in trust_signals:
        if signal not in deduped:
            deduped.append(signal)
    return deduped


def _build_risk_signals(
    keyword_matches: list[str],
    sender_matches: list[str],
    suspicious_urls: list[str],
    young_domains: list[str],
    ml_score: float,
    urgency_notes: list[str],
    header_issues: list[str],
    url_issues: list[str],
    attachment_issues: list[str],
    brand_alignment_issues: list[str],
) -> list[str]:
    signals: list[str] = []
    if keyword_matches:
        signals.append(f"Risky keywords detected: {', '.join(keyword_matches)}.")
    if sender_matches:
        signals.append("Sender naming pattern triggered risk heuristics: " + ", ".join(f"'{m}'" for m in sender_matches) + ".")
    if suspicious_urls:
        signals.append("Suspicious link domains detected: " + ", ".join(suspicious_urls) + ".")
    if young_domains:
        signals.append("One or more linked domains appear recently registered: " + ", ".join(young_domains) + ".")
    if ml_score >= 0.35:
        signals.append(f"The ML classifier assigned elevated phishing probability ({ml_score:.2f}).")
    signals.extend(urgency_notes)
    signals.extend(header_issues)
    signals.extend(url_issues)
    signals.extend(attachment_issues)
    signals.extend(brand_alignment_issues)
    return signals


def _recommended_actions(category: str, score: float) -> list[str]:
    if category in {"phishing", "suspicious"}:
        actions = [
            "Do not click links or open attachments until the sender is verified through an official channel.",
            "Inspect the sender domain, Reply-To, and destination URLs before taking any action.",
        ]
        if score >= PHISHING_THRESHOLD:
            actions.append("Escalate the message for human review if it targets credentials, payments, or account recovery.")
        return actions
    return [
        "You can review the message normally, but still verify destination domains before signing in.",
        "Keep normal caution around links and attachments even when the message looks legitimate.",
    ]


def _summary(prediction: str, risk_signals: list[str], trust_signals: list[str]) -> str:
    if prediction == "Phishing":
        if risk_signals:
            detail = risk_signals[0].rstrip(".")
            return "This email looks suspicious because " + detail[0].lower() + detail[1:] + "."
        return "This email looks suspicious because multiple phishing heuristics were triggered."
    if trust_signals:
        detail = trust_signals[0].rstrip(".")
        return "This email looks low risk because " + detail[0].lower() + detail[1:] + "."
    return "This email looks low risk because it did not trigger major phishing indicators."


async def detect_phishing(
    subject: str,
    sender: str,
    body: str,
    headers: dict[str, str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    links: list[dict[str, Any]] | None = None,
    body_text: str | None = None,
    body_html: str | None = None,
) -> DetectionResult:
    parsed_body = _parse_email_body(body_html or body)
    effective_text = body_text or parsed_body or body
    combined_text = _normalize_text(subject, sender, effective_text, parsed_body)
    processed_text = _preprocess_text(combined_text)
    sender_lower = sender.strip().lower()

    (
        (keyword_score, keyword_matches),
        (sender_score, sender_matches),
        (url_score, suspicious_urls, young_domains, url_issues, link_alignment_signals),
        ml_score,
        (urgency_score, urgency_notes),
    ) = await asyncio.gather(
        asyncio.to_thread(_keyword_analysis, processed_text),
        asyncio.to_thread(_sender_analysis, sender_lower),
        asyncio.to_thread(_url_analysis, sender, body, links, body_html),
        asyncio.to_thread(_ml_phishing_score, processed_text),
        asyncio.to_thread(_urgency_analysis, combined_text),
    )

    header_score, header_issues, header_trust_signals = _header_analysis(sender, headers)
    attachment_score, attachment_issues, attachment_trust = _attachment_analysis(attachments)
    alignment_score, alignment_issues, alignment_trust = _brand_alignment_score(sender, parsed_body, headers)
    marketing_signals = _marketing_trust_signals(parsed_body)
    transactional_signals = _transactional_trust_signals(parsed_body)

    raw_score = min(
        keyword_score
        + sender_score
        + url_score
        + ml_score * 0.22
        + urgency_score
        + header_score
        + attachment_score
        + alignment_score,
        1.0,
    )

    trust_signals = _build_trust_signals(
        sender,
        keyword_matches,
        suspicious_urls,
        urgency_score,
        header_trust_signals,
        marketing_signals,
        transactional_signals,
        link_alignment_signals,
        alignment_trust,
        attachment_trust,
    )
    trust_credit = min(
        0.12 if header_trust_signals else 0.0
        + 0.07 if marketing_signals else 0.0
        + 0.05 if transactional_signals else 0.0
        + 0.05 if link_alignment_signals else 0.0
        + 0.04 if alignment_trust else 0.0
        + 0.02 if attachment_trust else 0.0,
        0.24,
    )
    adjusted_score = max(raw_score - trust_credit, 0.0)

    risk_signals = _build_risk_signals(
        keyword_matches,
        sender_matches,
        suspicious_urls,
        young_domains,
        ml_score,
        urgency_notes,
        header_issues,
        url_issues,
        attachment_issues,
        alignment_issues,
    )

    matched_keywords: list[str] = []
    matched_keywords.extend(keyword_matches)
    matched_keywords.extend(f"sender:{marker}" for marker in sender_matches)
    matched_keywords.extend(f"suspicious_url:{url}" for url in suspicious_urls)
    if any(match in HIGH_RISK_PHRASES for match in keyword_matches):
        matched_keywords.append("high_risk_phrase")
    if ml_score >= 0.1:
        matched_keywords.append("ai_detected_phishing")
    if urgency_score >= 0.08:
        matched_keywords.append("high_urgency")
    if header_issues:
        matched_keywords.append("header_issues")
    if attachment_issues:
        matched_keywords.append("attachment_risk")
    if alignment_issues:
        matched_keywords.append("sender_alignment_issue")

    prediction = "Phishing" if adjusted_score >= PHISHING_THRESHOLD else "Safe"
    category = _classify_category(prediction, subject, parsed_body, adjusted_score, trust_signals, risk_signals, header_issues)
    if prediction == "Safe" and category == "suspicious" and adjusted_score >= SUSPICIOUS_THRESHOLD:
        category = "suspicious"

    confidence = adjusted_score if prediction == "Phishing" else 1.0 - adjusted_score
    risk_level = _classify_risk_level(adjusted_score)
    reason = (
        "Matched risky indicators: " + ", ".join(matched_keywords or ["multiple phishing heuristics"]) + "."
        if prediction == "Phishing"
        else (
            "Low-risk indicators detected, but legitimacy signals outweighed them."
            if risk_signals
            else "No major phishing patterns detected."
        )
    )

    return {
        "prediction": prediction,
        "category": category,
        "confidence": round(confidence, 3),
        "score": round(adjusted_score, 3),
        "risk_level": risk_level,
        "matched_keywords": matched_keywords,
        "reason": reason,
        "summary": _summary(prediction, risk_signals, trust_signals),
        "risk_signals": risk_signals,
        "trust_signals": trust_signals,
        "recommended_actions": _recommended_actions(category, adjusted_score),
        "analysis_breakdown": {
            "keyword": round(keyword_score, 3),
            "sender": round(sender_score, 3),
            "url": round(url_score, 3),
            "ml": round(ml_score * 0.22, 3),
            "urgency": round(urgency_score, 3),
            "headers": round(header_score, 3),
            "attachments": round(attachment_score, 3),
            "alignment": round(alignment_score, 3),
            "trust_credit": round(trust_credit, 3),
        },
    }
