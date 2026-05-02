from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import enum
import json
from pathlib import Path

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text, create_engine, text
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'phishguard.db'}"

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def utc_now() -> datetime:
    return datetime.now(UTC)


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


role_enum = Enum(
    UserRole,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
    native_enum=False,
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(role_enum, default=UserRole.USER, nullable=False)


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True)
    subject = Column(String, index=True)
    sender = Column(String)
    body = Column(Text)
    prediction = Column(String)
    category = Column(String, default="general_safe")
    confidence = Column(Float)
    score = Column(Float)
    risk_level = Column(String, default="Low")
    matched_keywords = Column(Text, default="[]")
    reason = Column(Text)
    summary = Column(Text, default="")
    risk_signals = Column(Text, default="[]")
    trust_signals = Column(Text, default="[]")
    recommended_actions = Column(Text, default="[]")
    analysis_breakdown = Column(Text, default="{}")
    headers = Column(Text, default="{}")
    attachment_metadata = Column(Text, default="[]")
    created_at = Column(DateTime(timezone=True), default=utc_now)

    feedback_items = relationship("Feedback", back_populates="detection_result")


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String, index=True)
    detection_result_id = Column(Integer, ForeignKey("detection_results.id"), nullable=True, index=True)
    actual_prediction = Column(String)
    user_feedback = Column(Text)
    admin_response = Column(Text, nullable=True)
    status = Column(String, default="open")
    matched_keywords = Column(Text, default="[]")
    reason = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utc_now)

    detection_result = relationship("DetectionResult", back_populates="feedback_items")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _json_default(value: str) -> str:
    return value


def _ensure_sqlite_columns() -> None:
    if not DATABASE_URL.startswith("sqlite:///"):
        return

    migrations = {
        "detection_results": {
            "category": "TEXT DEFAULT 'general_safe'",
            "risk_level": "TEXT DEFAULT 'Low'",
            "summary": "TEXT DEFAULT ''",
            "risk_signals": "TEXT DEFAULT '[]'",
            "trust_signals": "TEXT DEFAULT '[]'",
            "recommended_actions": "TEXT DEFAULT '[]'",
            "analysis_breakdown": "TEXT DEFAULT '{}'",
            "headers": "TEXT DEFAULT '{}'",
            "attachment_metadata": "TEXT DEFAULT '[]'",
        },
        "feedback": {
            "detection_result_id": "INTEGER",
            "admin_response": "TEXT",
            "status": "TEXT DEFAULT 'open'",
            "matched_keywords": "TEXT DEFAULT '[]'",
            "reason": "TEXT DEFAULT ''",
        },
        "users": {
            "role": "TEXT DEFAULT 'user' NOT NULL",
        },
    }

    with engine.begin() as connection:
        for table_name, columns in migrations.items():
            existing = {
                row[1]
                for row in connection.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
            }
            for column_name, ddl in columns.items():
                if column_name in existing:
                    continue
                connection.execute(
                    text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}")
                )


def init_db():
    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()


def dumps_json(value) -> str:
    return json.dumps(value, ensure_ascii=True)
