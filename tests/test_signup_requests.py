from __future__ import annotations

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
from backend.models import Base, RequestStatus, SignupRequest, User, UserRole, engine as app_engine, get_db


class SignupRequestFlowTestCase(unittest.TestCase):
    def setUp(self):
        self.artifact_dir = PROJECT_ROOT / "backend" / "tests" / ".artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.artifact_dir / f"signup_requests_{uuid.uuid4().hex}.db"
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
            admin_user = User(
                email="admin@phishguard.ai",
                hashed_password=pwd_context.hash("admin123"),
                role=UserRole.ADMIN,
            )
            db.add(admin_user)
            db.commit()
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

    def _admin_headers(self) -> dict[str, str]:
        login_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@phishguard.ai", "password": "admin123"},
        )
        self.assertEqual(login_response.status_code, 200)
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_signup_request_can_be_approved_into_real_user(self):
        request_payload = {
            "full_name": "Jane Analyst",
            "email": "jane@phishguard.ai",
            "password": "securepass123",
            "organization": "PhishGuard Labs",
        }

        create_response = self.client.post("/api/v1/auth/signup-request", json=request_payload)
        self.assertEqual(create_response.status_code, 200)

        list_response = self.client.get(
            "/api/v1/admin/signup-requests?status=pending",
            headers=self._admin_headers(),
        )
        self.assertEqual(list_response.status_code, 200)
        requests = list_response.json()
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["email"], "jane@phishguard.ai")

        approve_response = self.client.put(
            f"/api/v1/admin/signup-requests/{requests[0]['id']}/approve",
            headers=self._admin_headers(),
        )
        self.assertEqual(approve_response.status_code, 200)

        login_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "jane@phishguard.ai", "password": "securepass123"},
        )
        self.assertEqual(login_response.status_code, 200)
        self.assertEqual(login_response.json()["role"], "user")

    def test_signup_request_can_be_rejected_without_creating_user(self):
        request_payload = {
            "full_name": "Blocked User",
            "email": "blocked@phishguard.ai",
            "password": "securepass123",
            "organization": "Blocked Org",
        }

        create_response = self.client.post("/api/v1/auth/signup-request", json=request_payload)
        self.assertEqual(create_response.status_code, 200)

        db = self.TestingSessionLocal()
        try:
            signup_request = db.query(SignupRequest).filter(SignupRequest.email == "blocked@phishguard.ai").first()
            self.assertIsNotNone(signup_request)
            request_id = signup_request.id
        finally:
            db.close()

        reject_response = self.client.put(
            f"/api/v1/admin/signup-requests/{request_id}/reject",
            headers=self._admin_headers(),
        )
        self.assertEqual(reject_response.status_code, 200)

        db = self.TestingSessionLocal()
        try:
            signup_request = db.get(SignupRequest, request_id)
            created_user = db.query(User).filter(User.email == "blocked@phishguard.ai").first()
            self.assertEqual(signup_request.status, RequestStatus.REJECTED)
            self.assertIsNone(created_user)
        finally:
            db.close()

        login_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "blocked@phishguard.ai", "password": "securepass123"},
        )
        self.assertEqual(login_response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
