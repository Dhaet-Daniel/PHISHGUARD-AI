from __future__ import annotations

try:
    from backend.auth import pwd_context
    from backend.models import SessionLocal, User, UserRole, init_db
except ModuleNotFoundError:
    from auth import pwd_context
    from models import SessionLocal, User, UserRole, init_db


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(User.email == "admin@phishguard.ai").first()
        if existing_admin:
            print("Admin user already exists.")
            return

        admin = User(
            email="admin@phishguard.ai",
            hashed_password=pwd_context.hash("admin123"),
            role=UserRole.ADMIN,
        )
        db.add(admin)
        db.commit()
        print("Admin user created.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
