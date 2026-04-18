from __future__ import annotations

import unittest
from pathlib import Path
import sys
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.main import app
from backend.models import Base, engine as app_engine, get_db


class APITestCase(unittest.TestCase):
    def setUp(self):
        self.artifact_dir = PROJECT_ROOT / "backend" / "tests" / ".artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.artifact_dir / f"test_{uuid.uuid4().hex}.db"
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
        )
        self.TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app_engine.dispose()
        if self.db_path.exists():
            self.db_path.unlink()

    def test_predict_endpoint_returns_explainable_result(self):
        payload = {
            "subject": "Host Your Own Hackathon on Kaggle Now!",
            "sender_info": {
                "email": "no-reply@kaggle.com",
                "display_name": "Kaggle",
                "reply_to": "no-reply@kaggle.com",
                "return_path": "bounce@kaggle.com",
            },
            "body_text": (
                "Community Hackathons are now available to all Kaggle users at no cost. "
                "Learn more at https://www.kaggle.com/. You can unsubscribe or update your preferences."
            ),
            "body_html": (
                "<html><body><a href='https://www.kaggle.com/'>Learn more</a>"
                "<p>You can unsubscribe or update your preferences.</p></body></html>"
            ),
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.kaggle.com by mx.google.com",
                "Reply-To": "no-reply@kaggle.com",
                "Return-Path": "<bounce@kaggle.com>",
            },
            "links": [{"text": "Learn more", "url": "https://www.kaggle.com/", "source": "html"}],
            "attachments": [],
        }

        response = self.client.post("/api/v1/predict", json=payload)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIsNotNone(body["record_id"])
        self.assertEqual(body["prediction"], "Safe")
        self.assertIn(body["category"], {"legitimate_marketing", "general_safe", "transactional", "security_notice", "suspicious"})
        self.assertIn("risk_signals", body)
        self.assertIn("trust_signals", body)
        self.assertIn("analysis_breakdown", body)

    def test_predict_endpoint_rejects_invalid_sender(self):
        payload = {
            "subject": "Hi there",
            "sender": "not-an-email",
            "body_text": "This body is long enough to pass length validation.",
            "headers": {},
            "attachments": [],
        }

        response = self.client.post("/api/v1/predict", json=payload)

        self.assertEqual(response.status_code, 422)

    def test_batch_predict_endpoint_returns_multiple_results(self):
        payload = [
            {
                "subject": "Your order receipt from Example Store",
                "sender_info": {
                    "email": "receipts@example-store.com",
                    "reply_to": "receipts@example-store.com",
                    "return_path": "receipts@example-store.com",
                },
                "body_text": "Thank you for your order. View your receipt at https://example-store.com/orders/12345.",
                "headers": {
                    "Authentication-Results": "spf=pass; dkim=pass",
                    "Received": "from mail.example-store.com by mx.google.com",
                    "Reply-To": "receipts@example-store.com",
                    "Return-Path": "<receipts@example-store.com>",
                },
                "attachments": [
                    {
                        "filename": "receipt.pdf",
                        "content_type": "application/pdf",
                        "size": 184320,
                    }
                ],
            },
            {
                "raw_email": (
                    "From: Security Team <security-team@safe-payments-alert.com>\n"
                    "Reply-To: support@credential-check.xyz\n"
                    "Return-Path: <mailer@credential-check.xyz>\n"
                    "Subject: Urgent: Verify your payroll account\n"
                    "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
                    "Content-Type: text/plain; charset=utf-8\n\n"
                    "Click here immediately to confirm your identity and reset your password: "
                    "http://bit.ly/payroll-reset"
                ),
                "attachments": [],
            },
        ]

        response = self.client.post("/api/v1/batch-predict", json=payload)

        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 2)
        self.assertTrue(all("prediction" in result for result in results))
        self.assertTrue(all("category" in result for result in results))
        self.assertTrue(all(result["record_id"] is not None for result in results))

    def test_batch_predict_endpoint_enforces_limit(self):
        email = {
            "subject": "Host Your Own Hackathon on Kaggle Now!",
            "sender": "no-reply@kaggle.com",
            "body_text": "Community Hackathons are now available to all Kaggle users. Learn more at https://www.kaggle.com/.",
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.kaggle.com by mx.google.com",
                "Reply-To": "no-reply@kaggle.com",
                "Return-Path": "<bounce@kaggle.com>",
            },
            "attachments": [],
        }

        response = self.client.post("/api/v1/batch-predict", json=[email] * 11)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Batch size limited to 10 emails")

    def test_feedback_endpoint_accepts_linked_feedback(self):
        prediction_payload = {
            "subject": "Your weekly GitHub activity summary",
            "sender_info": {
                "email": "notifications@github.com",
                "reply_to": "notifications@github.com",
                "return_path": "notifications@github.com",
            },
            "body_text": "Review your notifications at https://github.com/notifications and update your email preferences anytime.",
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.github.com by mx.google.com",
                "Reply-To": "notifications@github.com",
                "Return-Path": "<notifications@github.com>",
            },
            "attachments": [],
        }

        predict_response = self.client.post("/api/v1/predict", json=prediction_payload)
        record_id = predict_response.json()["record_id"]

        feedback_payload = {
            "detection_result_id": record_id,
            "actual_prediction": "Safe",
            "user_feedback": "This is a legitimate GitHub digest email.",
            "matched_keywords": ["brand_match", "newsletter_footer"],
            "reason": "Trusted domain and aligned headers.",
        }

        response = self.client.post("/api/v1/feedback", json=feedback_payload)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["message"], "Feedback submitted successfully")
        self.assertIsNotNone(body["feedback_id"])

    def test_feedback_endpoint_requires_reference(self):
        response = self.client.post(
            "/api/v1/feedback",
            json={
                "actual_prediction": "Safe",
                "user_feedback": "No linked record.",
                "matched_keywords": [],
                "reason": "Missing id should fail.",
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_recent_results_endpoint_returns_saved_records(self):
        first_payload = {
            "subject": "Host Your Own Hackathon on Kaggle Now!",
            "sender": "no-reply@kaggle.com",
            "body_text": "Community Hackathons are now available to all Kaggle users at no cost. Learn more at https://www.kaggle.com/.",
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.kaggle.com by mx.google.com",
                "Reply-To": "no-reply@kaggle.com",
                "Return-Path": "<bounce@kaggle.com>",
            },
            "attachments": [],
        }
        second_payload = {
            "raw_email": (
                "From: Security Team <security-team@safe-payments-alert.com>\n"
                "Reply-To: support@credential-check.xyz\n"
                "Return-Path: <mailer@credential-check.xyz>\n"
                "Subject: Urgent: Verify your payroll account\n"
                "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "Click here immediately to confirm your identity and reset your password: "
                "http://bit.ly/payroll-reset"
            ),
            "attachments": [],
        }

        self.client.post("/api/v1/predict", json=first_payload)
        self.client.post("/api/v1/predict", json=second_payload)

        response = self.client.get("/api/v1/results/recent?limit=2")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["count"], 2)
        self.assertEqual(len(body["results"]), 2)
        self.assertIn("record_id", body["results"][0])
        self.assertIn("created_at", body["results"][0])

    def test_result_detail_endpoint_returns_record_and_feedback(self):
        prediction_payload = {
            "subject": "Your weekly GitHub activity summary",
            "sender_info": {
                "email": "notifications@github.com",
                "reply_to": "notifications@github.com",
                "return_path": "notifications@github.com",
            },
            "body_text": "Review your notifications at https://github.com/notifications and update your email preferences anytime.",
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                "Received": "from mail.github.com by mx.google.com",
                "Reply-To": "notifications@github.com",
                "Return-Path": "<notifications@github.com>",
            },
            "attachments": [],
        }

        predict_response = self.client.post("/api/v1/predict", json=prediction_payload)
        record_id = predict_response.json()["record_id"]

        feedback_payload = {
            "detection_result_id": record_id,
            "actual_prediction": "Safe",
            "user_feedback": "This is a legitimate GitHub digest email.",
            "matched_keywords": ["brand_match", "newsletter_footer"],
            "reason": "Trusted domain and aligned headers.",
        }
        self.client.post("/api/v1/feedback", json=feedback_payload)

        response = self.client.get(f"/api/v1/results/{record_id}")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["record_id"], record_id)
        self.assertIn("analysis_breakdown", body)
        self.assertIn("headers", body)
        self.assertIn("attachment_metadata", body)
        self.assertEqual(len(body["feedback"]), 1)
        self.assertEqual(body["feedback"][0]["detection_result_id"], record_id)

    def test_result_detail_endpoint_returns_404_for_missing_record(self):
        response = self.client.get("/api/v1/results/999999")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Analysis record not found")


if __name__ == "__main__":
    unittest.main()
