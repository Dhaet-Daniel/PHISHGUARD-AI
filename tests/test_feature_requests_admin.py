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

from backend.auth import create_access_token
from backend.main import app
from backend.models import Base, FeatureRequest, User, UserFeature, UserRole, engine as app_engine, get_db


class AdminFeatureRequestFlowTestCase(unittest.TestCase):
    def setUp(self):
        self.artifact_dir = PROJECT_ROOT / "backend" / "tests" / ".artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.artifact_dir / f"feature_requests_admin_{uuid.uuid4().hex}.db"
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
        self.admin_headers = {
            "Authorization": f"Bearer {create_access_token({'sub': 'admin@phishguard.ai', 'role': 'admin'})}"
        }

        db = self.TestingSessionLocal()
        try:
            db.add_all(
                [
                    User(
                        email="admin@phishguard.ai",
                        hashed_password="placeholder",
                        role=UserRole.ADMIN,
                    ),
                    User(
                        email="user@phishguard.ai",
                        hashed_password="placeholder",
                        role=UserRole.USER,
                    ),
                ]
            )
            db.add(
                FeatureRequest(
                    user_email="user@phishguard.ai",
                    feature_name="ENABLE_TRANSFORMERS",
                    status="pending",
                )
            )
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

    def test_admin_can_list_feature_requests(self):
        response = self.client.get(
            "/api/v1/admin/feature-requests",
            headers=self.admin_headers,
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["user_email"], "user@phishguard.ai")
        self.assertEqual(body[0]["feature_name"], "ENABLE_TRANSFORMERS")
        self.assertEqual(body[0]["status"], "pending")
        self.assertIn("created_at", body[0])

    def test_admin_can_resolve_feature_request(self):
        db = self.TestingSessionLocal()
        try:
            feature_request = db.query(FeatureRequest).first()
            request_id = feature_request.id
        finally:
            db.close()

        response = self.client.put(
            f"/api/v1/admin/feature-requests/{request_id}/resolve",
            headers=self.admin_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["message"],
            "Feature ENABLE_TRANSFORMERS enabled for user@phishguard.ai",
        )

        db = self.TestingSessionLocal()
        try:
            updated_request = db.get(FeatureRequest, request_id)
            user = db.query(User).filter(User.email == "user@phishguard.ai").first()
            override = db.query(UserFeature).filter_by(
                user_id=user.id,
                feature_name="ENABLE_TRANSFORMERS",
            ).first()
            self.assertEqual(updated_request.status, "approved")
            self.assertIsNotNone(override)
            self.assertTrue(override.enabled)
        finally:
            db.close()

    def test_admin_can_dismiss_feature_request(self):
        db = self.TestingSessionLocal()
        try:
            feature_request = db.query(FeatureRequest).first()
            request_id = feature_request.id
        finally:
            db.close()

        response = self.client.put(
            f"/api/v1/admin/feature-requests/{request_id}/dismiss",
            headers=self.admin_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Request dismissed")

        db = self.TestingSessionLocal()
        try:
            updated_request = db.get(FeatureRequest, request_id)
            self.assertEqual(updated_request.status, "dismissed")
        finally:
            db.close()
