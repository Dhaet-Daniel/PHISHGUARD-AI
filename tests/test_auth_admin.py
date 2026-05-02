from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.auth import pwd_context
from backend.main import app
from backend.models import Base, DetectionResult, Feedback, User, UserRole, engine as app_engine, get_db


class AuthAdminAPITestCase(unittest.TestCase):
    def setUp(self):
        self.artifact_dir = PROJECT_ROOT / "backend" / "tests" / ".artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.artifact_dir / f"auth_admin_{uuid.uuid4().hex}.db"
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

        db = self.TestingSessionLocal()
        try:
            self.admin_user = User(
                email="admin@phishguard.ai",
                hashed_password=pwd_context.hash("admin123"),
                role=UserRole.ADMIN,
            )
            self.standard_user = User(
                email="user@phishguard.ai",
                hashed_password=pwd_context.hash("user123"),
                role=UserRole.USER,
            )
            db.add_all([self.admin_user, self.standard_user])
            db.commit()
            db.refresh(self.admin_user)
            db.refresh(self.standard_user)

            self.result = DetectionResult(
                subject="Security notice",
                sender="alerts@example.com",
                body="Please review your account activity.",
                prediction="Safe",
                category="security_notice",
                confidence=0.88,
                score=0.12,
                risk_level="Low",
                matched_keywords=json.dumps(["account"]),
                reason="Trusted sender domain with aligned headers.",
                summary="Low-risk security notice.",
                risk_signals=json.dumps([]),
                trust_signals=json.dumps(["Known sender domain"]),
                recommended_actions=json.dumps(["Review normally"]),
                analysis_breakdown=json.dumps({"headers": 0.0, "sender": 0.0}),
                headers=json.dumps({"Authentication-Results": "spf=pass"}),
                attachment_metadata=json.dumps([]),
            )
            db.add(self.result)
            db.commit()
            db.refresh(self.result)
            self.result_id = self.result.id

            self.feedback = Feedback(
                email_id=str(self.result.id),
                detection_result_id=self.result.id,
                actual_prediction="Safe",
                user_feedback="This was legitimate.",
                admin_response=None,
                status="open",
                matched_keywords=json.dumps(["trusted_domain"]),
                reason="Aligned sender domain.",
            )
            db.add(self.feedback)
            db.commit()
            db.refresh(self.feedback)
            self.feedback_id = self.feedback.id
        finally:
            db.close()

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app_engine.dispose()
        if self.db_path.exists():
            self.db_path.unlink()

    def _login(self, email: str, password: str) -> str:
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["access_token"]

    def test_login_returns_token_and_role(self):
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@phishguard.ai", "password": "admin123"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["token_type"], "bearer")
        self.assertEqual(body["role"], "admin")
        self.assertTrue(body["access_token"])

    def test_admin_routes_require_admin_role(self):
        user_token = self._login("user@phishguard.ai", "user123")

        unauthenticated = self.client.get("/api/v1/admin/users")
        forbidden = self.client.get(
            "/api/v1/admin/users",
            headers={"Authorization": f"Bearer {user_token}"},
        )

        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(forbidden.status_code, 403)

    def test_admin_user_crud(self):
        admin_token = self._login("admin@phishguard.ai", "admin123")
        headers = {"Authorization": f"Bearer {admin_token}"}

        create_response = self.client.post(
            "/api/v1/admin/users",
            json={
                "email": "analyst@phishguard.ai",
                "password": "analyst123",
                "role": "user",
            },
            headers=headers,
        )
        self.assertEqual(create_response.status_code, 201)
        created_user = create_response.json()
        self.assertEqual(created_user["email"], "analyst@phishguard.ai")
        self.assertEqual(created_user["role"], "user")

        list_response = self.client.get("/api/v1/admin/users", headers=headers)
        self.assertEqual(list_response.status_code, 200)
        self.assertTrue(any(user["email"] == "analyst@phishguard.ai" for user in list_response.json()))

        update_response = self.client.put(
            f"/api/v1/admin/users/{created_user['id']}",
            json={"role": "admin"},
            headers=headers,
        )
        self.assertEqual(update_response.status_code, 200)
        self.assertEqual(update_response.json()["role"], "admin")

        delete_response = self.client.delete(
            f"/api/v1/admin/users/{created_user['id']}",
            headers=headers,
        )
        self.assertEqual(delete_response.status_code, 204)

    def test_admin_results_and_stats(self):
        admin_token = self._login("admin@phishguard.ai", "admin123")
        headers = {"Authorization": f"Bearer {admin_token}"}

        results_response = self.client.get("/api/v1/admin/results", headers=headers)
        self.assertEqual(results_response.status_code, 200)
        results = results_response.json()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["record_id"], self.result_id)

        stats_response = self.client.get("/api/v1/admin/stats", headers=headers)
        self.assertEqual(stats_response.status_code, 200)
        self.assertEqual(stats_response.json()["total_users"], 2)
        self.assertEqual(stats_response.json()["total_scans"], 1)
        self.assertEqual(stats_response.json()["open_feedback"], 1)

        delete_response = self.client.delete(
            f"/api/v1/admin/results/{self.result_id}",
            headers=headers,
        )
        self.assertEqual(delete_response.status_code, 204)

    def test_admin_feedback_update_and_delete(self):
        admin_token = self._login("admin@phishguard.ai", "admin123")
        headers = {"Authorization": f"Bearer {admin_token}"}

        list_response = self.client.get("/api/v1/admin/feedback", headers=headers)
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()), 1)

        update_response = self.client.put(
            f"/api/v1/admin/feedback/{self.feedback_id}",
            json={"admin_response": "Reviewed and resolved.", "status": "resolved"},
            headers=headers,
        )
        self.assertEqual(update_response.status_code, 200)
        updated_feedback = update_response.json()
        self.assertEqual(updated_feedback["admin_response"], "Reviewed and resolved.")
        self.assertEqual(updated_feedback["status"], "resolved")

        delete_response = self.client.delete(
            f"/api/v1/admin/feedback/{self.feedback_id}",
            headers=headers,
        )
        self.assertEqual(delete_response.status_code, 204)


if __name__ == "__main__":
    unittest.main()
