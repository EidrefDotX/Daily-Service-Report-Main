import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Any, Dict

from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]
from flask import Flask, jsonify, request, send_from_directory  # pyright: ignore[reportMissingImports]
from flask_cors import CORS  # pyright: ignore[reportMissingModuleSource]
from sqlalchemy import Column, Integer, String, Text, DateTime, create_engine, select, text  # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import declarative_base, sessionmaker, Session, Mapped, mapped_column  # pyright: ignore[reportMissingImports]
from werkzeug.security import generate_password_hash, check_password_hash  # pyright: ignore[reportMissingImports]
import jwt  # pyright: ignore[reportMissingImports]
import secrets


# Load environment from working directory and explicitly from backend/.env for robustness
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


def create_app() -> Flask:
    app = Flask(__name__)

    # Secrets
    app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")
    jwt_secret = os.getenv("JWT_SECRET", app.secret_key)
    jwt_expire_minutes = int(os.getenv("JWT_EXPIRE_MINUTES", "120"))

    # Allow requests from file:// and http(s)://localhost environments
    CORS(
        app,
        resources={r"/*": {"origins": "*"}},
        supports_credentials=False,
        allow_headers=["Content-Type", "Authorization"],
        expose_headers=["Content-Type"],
    )

    # Resolve project root to serve frontend assets
    project_root = os.path.abspath(os.path.dirname(__file__))

    database_url: Optional[str] = os.getenv("DATABASE_URL")
    sqlite_path = os.path.join(os.path.dirname(__file__), "dsr.sqlite3")
    if not database_url:
        database_url = f"sqlite:///{sqlite_path}"
        print("[backend] DATABASE_URL not set. Using SQLite at:", sqlite_path)

    # Create engine with graceful fallback to SQLite if the configured DB is unreachable
    def create_engine_with_fallback(url: str):
        eng = create_engine(url, pool_pre_ping=True, future=True)
        try:
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return eng
        except Exception as exc:
            print("[backend] Primary DATABASE_URL connection failed:", str(exc))
            print("[backend] Falling back to SQLite at:", sqlite_path)
            return create_engine(f"sqlite:///{sqlite_path}", pool_pre_ping=True, future=True)

    engine = create_engine_with_fallback(database_url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    Base = declarative_base()

    class Report(Base):  # type: ignore[name-defined]
        __tablename__ = "reports"

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        report_date: Mapped[str] = mapped_column(String(10), nullable=False)  # YYYY-MM-DD
        engineer_name: Mapped[str] = mapped_column(String(255), nullable=False)
        project_name: Mapped[str] = mapped_column(String(255), nullable=False)
        project_code: Mapped[str] = mapped_column(String(255), nullable=False)

        travel_time_to_site: Mapped[str] = mapped_column(String(5), nullable=False)   # HH:MM
        travel_time_from_site: Mapped[str] = mapped_column(String(5), nullable=False) # HH:MM
        onsite_time_in: Mapped[str] = mapped_column(String(5), nullable=False)        # HH:MM
        onsite_time_out: Mapped[str] = mapped_column(String(5), nullable=False)       # HH:MM

        work_objective: Mapped[str] = mapped_column(Text, nullable=False)
        description: Mapped[str] = mapped_column(Text, nullable=False)
        outcome: Mapped[str] = mapped_column(Text, nullable=False)

        engineer_signature: Mapped[str] = mapped_column(String(255), nullable=False)
        customer_signature: Mapped[str] = mapped_column(String(255), nullable=False)

        created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    class User(Base):  # type: ignore[name-defined]
        __tablename__ = "users"

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
        password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
        role: Mapped[str] = mapped_column(String(20), nullable=False, default="client")  # 'admin' | 'client'
        created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    class PasswordResetToken(Base):  # type: ignore[name-defined]
        __tablename__ = "password_reset_tokens"

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        user_id: Mapped[int] = mapped_column(Integer, nullable=False)
        token: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
        expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

    def get_db_session() -> Session:
        return SessionLocal()

    # Initialize default engineer users if they don't exist
    def init_default_users():
        """Create default engineer users on startup"""
        default_engineers = {
            'EN001': 'Reherns',
            'EN002': 'Sam',
            'EN003': 'Ramil',
            'EN004': 'Vin',
            'EN005': 'Renz',
            'EN006': 'Brent',
            'EN007': 'Anwil',
            'EN008': 'Issa',
            'EN009': 'Ana'
        }
        default_password = '#DotXsolutions.opc'
        
        db = get_db_session()
        try:
            for code, name in default_engineers.items():
                existing = db.execute(select(User).where(User.username == code)).scalar_one_or_none()
                if existing is None:
                    user = User(
                        username=code,
                        password_hash=generate_password_hash(default_password),
                        role='client'
                    )
                    db.add(user)
                    print(f"[backend] Created default user: {code} ({name})")
            db.commit()
        except Exception as e:
            print(f"[backend] Error creating default users: {e}")
            db.rollback()
        finally:
            db.close()
    
    init_default_users()

    def init_default_admin():
        """Create a default admin user if configured and missing."""
        admin_username = os.getenv("ADMIN_USERNAME", "admin").strip()
        admin_password = os.getenv("ADMIN_PASSWORD", "admin#ChangeMe1")
        if not admin_username or not admin_password:
            return
        db = get_db_session()
        try:
            existing_admin = db.execute(select(User).where(User.username == admin_username)).scalar_one_or_none()
            if existing_admin is None:
                user = User(
                    username=admin_username,
                    password_hash=generate_password_hash(admin_password),
                    role="admin",
                )
                db.add(user)
                db.commit()
                print(f"[backend] Created default admin user: {admin_username}")
        except Exception as e:
            print(f"[backend] Error creating default admin: {e}")
            db.rollback()
        finally:
            db.close()

    init_default_admin()

    @app.get("/health")
    def health() -> Tuple[dict, int]:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return {"status": "ok"}, 200
        except Exception as exc:  # noqa: BLE001 - report health failure details
            return {"status": "error", "detail": str(exc)}, 500

    @app.get("/")
    def root():  # type: ignore[no-untyped-def]
        # Serve login page as the startup page
        return send_from_directory(project_root, "login.html")

    @app.get("/DSR.html")
    def dsr_html():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "DSR.html")

    @app.get("/manifest.json")
    def manifest():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "manifest.json")

    @app.get("/service-worker.js")
    def service_worker():  # type: ignore[no-untyped-def]
        # Service workers must be served from the top-level scope
        return send_from_directory(project_root, "service-worker.js")

    @app.get("/sw.js")
    def sw_js():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "sw.js")

    @app.get("/login.html")
    def login_html():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "login.html")

    @app.get("/login")
    def login_route():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "login.html")

    @app.get("/auth.js")
    def auth_js():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "auth.js")

    @app.get("/admin.html")
    def admin_html():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "admin.html")


    def create_reset_token() -> str:
        return secrets.token_urlsafe(32)

    def create_jwt(user: "User") -> str:
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=jwt_expire_minutes),
            "iat": datetime.now(tz=timezone.utc),
        }
        return jwt.encode(payload, jwt_secret, algorithm="HS256")

    def get_user_from_token() -> Optional[Dict[str, Any]]:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        except Exception:
            return None
        user_id = payload.get("sub")
        if not user_id:
            return None
        db: Session = get_db_session()
        try:
            user = db.execute(select(User).where(User.id == int(user_id))).scalar_one_or_none()
            if user is None:
                return None
            return {"id": user.id, "username": user.username, "role": user.role}
        finally:
            db.close()

    def validate_time_format(time_str: str) -> bool:
        """Validate time format is HH:MM with valid hours (00-23) and minutes (00-59)"""
        if not time_str or not isinstance(time_str, str):
            return False
        pattern = r'^([0-1][0-9]|2[0-3]):([0-5][0-9])$'
        return bool(re.match(pattern, time_str))

    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """Validate password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
        return True, ""

    @app.route("/auth/login", methods=["POST", "OPTIONS"])
    def auth_login():  # type: ignore[no-untyped-def]
        if request.method == "OPTIONS":
            return ("", 204)
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        username = (payload or {}).get("username", "").strip()
        password = (payload or {}).get("password", "")
        if not username or not password:
            return jsonify({"ok": False, "error": "Username and password are required"}), 400

        db: Session = get_db_session()
        try:
            user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None or not check_password_hash(user.password_hash, password):
                return jsonify({"ok": False, "error": "Invalid credentials"}), 401
            token = create_jwt(user)
            return jsonify({"ok": True, "token": token, "user": {"username": user.username, "role": user.role}}), 200
        finally:
            db.close()

    @app.post("/auth/logout")
    def auth_logout():  # type: ignore[no-untyped-def]
        # Stateless JWT: client should discard the token
        return jsonify({"ok": True}), 200

    @app.get("/auth/me")
    def auth_me():  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user:
            return jsonify({"ok": True, "authenticated": False}), 200
        return jsonify({"ok": True, "authenticated": True, "user": user}), 200

    @app.post("/auth/register")
    def auth_register():  # type: ignore[no-untyped-def]
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        username = (payload or {}).get("username", "").strip()
        password = (payload or {}).get("password", "")
        role = (payload or {}).get("role", "client").strip().lower()
        if role not in ("client", "admin"):
            role = "client"
        if not username or not password:
            return jsonify({"ok": False, "error": "Username and password are required"}), 400
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            return jsonify({"ok": False, "error": error_msg}), 400

        db: Session = get_db_session()
        try:
            exists = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if exists is not None:
                return jsonify({"ok": False, "error": "Username already exists"}), 400

            # Only allow creating admin users when there is an authenticated admin
            if role == "admin":
                requester = get_user_from_token()
                if requester is None or requester.get("role") != "admin":
                    return jsonify({"ok": False, "error": "Forbidden"}), 403

            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
            )
            db.add(user)
            db.commit()
            return jsonify({"ok": True}), 201
        finally:
            db.close()

    @app.post("/auth/password/reset/request")
    def password_reset_request():  # type: ignore[no-untyped-def]
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        username = (payload or {}).get("username", "").strip()
        if not username:
            return jsonify({"ok": False, "error": "Username is required"}), 400
        db: Session = get_db_session()
        try:
            user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None:
                # Do not reveal existence
                return jsonify({"ok": True}), 200
            token = create_reset_token()
            # Use timezone-aware UTC datetime
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
            # Invalidate old tokens for this user
            db.execute(
                text("DELETE FROM password_reset_tokens WHERE user_id = :uid"),
                {"uid": user.id},
            )
            prt = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
            db.add(prt)
            db.commit()
            # SECURITY WARNING: In production, send this token via email/SMS
            # Returning it in the response is a security risk and should only be used for development/testing
            return jsonify({"ok": True, "resetToken": token}), 200
        finally:
            db.close()

    @app.post("/auth/password/reset/confirm")
    def password_reset_confirm():  # type: ignore[no-untyped-def]
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        token = (payload or {}).get("token", "").strip()
        new_password = (payload or {}).get("newPassword", "")
        if not token or not new_password:
            return jsonify({"ok": False, "error": "Token and newPassword are required"}), 400
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({"ok": False, "error": error_msg}), 400
        db: Session = get_db_session()
        try:
            record = db.execute(
                select(PasswordResetToken).where(PasswordResetToken.token == token)
            ).scalar_one_or_none()
            # Compare using timezone-aware UTC datetime
            if (record is None) or (record.expires_at < datetime.now(timezone.utc)):
                return jsonify({"ok": False, "error": "Invalid or expired token"}), 400
            user = db.execute(select(User).where(User.id == record.user_id)).scalar_one_or_none()
            if user is None:
                return jsonify({"ok": False, "error": "Invalid token"}), 400
            # Update via ORM attribute is fine; ensure proper typing by using mapped attribute
            user.password_hash = generate_password_hash(new_password)
            # Consume token
            db.execute(text("DELETE FROM password_reset_tokens WHERE id = :id"), {"id": record.id})
            db.commit()
            return jsonify({"ok": True}), 200
        finally:
            db.close()

    @app.post("/submit_report")
    def submit_report():  # type: ignore[no-untyped-def]
        # Authentication optional: allow submissions without JWT
        
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        required_fields = [
            "reportDate",
            "engineerName",
            "projectName",
            "projectCode",
            "travelTimeToSite",
            "travelTimeFromSite",
            "onSiteTimeIn",
            "onSiteTimeOut",
            "workObjective",
            "description",
            "outcome",
            "engineerSignature",
            "customerSignature",
        ]

        missing = [field for field in required_fields if not payload.get(field)]
        if missing:
            return jsonify({"ok": False, "error": "Missing required fields", "fields": missing}), 400
        
        # Validate time formats
        time_fields = {
            "travelTimeToSite": payload.get("travelTimeToSite"),
            "travelTimeFromSite": payload.get("travelTimeFromSite"),
            "onSiteTimeIn": payload.get("onSiteTimeIn"),
            "onSiteTimeOut": payload.get("onSiteTimeOut"),
        }
        for field_name, field_value in time_fields.items():
            if not validate_time_format(field_value):
                return jsonify({"ok": False, "error": f"Invalid time format for {field_name}. Expected HH:MM (00:00-23:59)"}), 400

        new_report = Report(
            report_date=payload["reportDate"],
            engineer_name=payload["engineerName"],
            project_name=payload["projectName"],
            project_code=payload["projectCode"],
            travel_time_to_site=payload["travelTimeToSite"],
            travel_time_from_site=payload["travelTimeFromSite"],
            onsite_time_in=payload["onSiteTimeIn"],
            onsite_time_out=payload["onSiteTimeOut"],
            work_objective=payload["workObjective"],
            description=payload["description"],
            outcome=payload["outcome"],
            engineer_signature=payload["engineerSignature"],
            customer_signature=payload["customerSignature"],
        )

        session = get_db_session()
        try:
            session.add(new_report)
            session.commit()
            session.refresh(new_report)
            return jsonify({"ok": True, "status": "ok", "id": new_report.id}), 200
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            return jsonify({"ok": False, "error": "Database error", "detail": str(exc)}), 500
        finally:
            session.close()

    @app.get("/reports")
    def list_reports():  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403

        engineer = (request.args.get("engineer") or "").strip()
        project_code = (request.args.get("project_code") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        q = (request.args.get("q") or "").strip()

        db: Session = get_db_session()
        try:
            stmt = select(Report)
            if engineer:
                stmt = stmt.where(Report.engineer_name.ilike(f"%{engineer}%"))
            if project_code:
                stmt = stmt.where(Report.project_code.ilike(f"%{project_code}%"))
            if date_from:
                stmt = stmt.where(Report.report_date >= date_from)
            if date_to:
                stmt = stmt.where(Report.report_date <= date_to)
            if q:
                like = f"%{q}%"
                stmt = stmt.where(
                    (Report.work_objective.ilike(like)) |
                    (Report.description.ilike(like)) |
                    (Report.outcome.ilike(like)) |
                    (Report.project_name.ilike(like))
                )
            stmt = stmt.order_by(Report.created_at.desc())
            rows = db.execute(stmt).scalars().all()

            def to_dict(r: "Report") -> dict:
                return {
                    "id": r.id,
                    "reportDate": r.report_date,
                    "engineerName": r.engineer_name,
                    "projectName": r.project_name,
                    "projectCode": r.project_code,
                    "travelTimeToSite": r.travel_time_to_site,
                    "travelTimeFromSite": r.travel_time_from_site,
                    "onSiteTimeIn": r.onsite_time_in,
                    "onSiteTimeOut": r.onsite_time_out,
                    "workObjective": r.work_objective,
                    "description": r.description,
                    "outcome": r.outcome,
                    "createdAt": r.created_at.isoformat(),
                }

            return jsonify({"ok": True, "items": [to_dict(r) for r in rows]}), 200
        finally:
            db.close()

    @app.get("/reports/<int:report_id>")
    def get_report(report_id: int):  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403

        db: Session = get_db_session()
        try:
            r = db.execute(select(Report).where(Report.id == report_id)).scalar_one_or_none()
            if r is None:
                return jsonify({"ok": False, "error": "Not found"}), 404
            return jsonify({
                "ok": True,
                "item": {
                    "id": r.id,
                    "reportDate": r.report_date,
                    "engineerName": r.engineer_name,
                    "projectName": r.project_name,
                    "projectCode": r.project_code,
                    "travelTimeToSite": r.travel_time_to_site,
                    "travelTimeFromSite": r.travel_time_from_site,
                    "onSiteTimeIn": r.onsite_time_in,
                    "onSiteTimeOut": r.onsite_time_out,
                    "workObjective": r.work_objective,
                    "description": r.description,
                    "outcome": r.outcome,
                    "engineerSignature": r.engineer_signature,
                    "customerSignature": r.customer_signature,
                    "createdAt": r.created_at.isoformat(),
                }
            }), 200
        finally:
            db.close()


    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    app.run(host=host, port=port, debug=debug)


