import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Any, Dict

from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]
from flask import Flask, jsonify, request, send_from_directory, Response  # pyright: ignore[reportMissingImports]
from flask_cors import CORS  # pyright: ignore[reportMissingModuleSource]
from sqlalchemy import Integer, String, Text, DateTime, create_engine, select, text  # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import declarative_base, sessionmaker, Session, Mapped, mapped_column  # pyright: ignore[reportMissingImports]
from werkzeug.security import generate_password_hash, check_password_hash  # pyright: ignore[reportMissingImports]
import jwt  # pyright: ignore[reportMissingImports]
import secrets


# Load environment from working directory and explicitly from backend/.env for robustness
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


def create_app() -> Flask:
    app = Flask(__name__)

    # Detect production environment
    flask_env = os.getenv("FLASK_ENV", "").lower()
    environment = os.getenv("ENVIRONMENT", "").lower()
    flask_debug = os.getenv("FLASK_DEBUG", "").lower()
    is_production = (
        flask_env == "production" or 
        environment == "production" or 
        (flask_debug == "false") or
        bool(os.getenv("PORT"))  # Render and most platforms set PORT
    )

    # Secrets - fail in production if not set
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        if is_production:
            raise ValueError("SECRET_KEY environment variable must be set in production")
        secret_key = "dev-secret-change-me"
        print("[WARNING] Using default SECRET_KEY. Set SECRET_KEY environment variable in production!")
    
    app.secret_key = secret_key
    jwt_secret = os.getenv("JWT_SECRET", app.secret_key)
    if is_production and jwt_secret == app.secret_key and not os.getenv("JWT_SECRET"):
        print("[WARNING] JWT_SECRET not set, using SECRET_KEY. Consider setting a separate JWT_SECRET in production.")
    jwt_expire_minutes = int(os.getenv("JWT_EXPIRE_MINUTES", "120"))

    # Configurable CORS (production: set CORS_ORIGINS to a comma-separated list)
    cors_origins = os.getenv("CORS_ORIGINS", "*")
    if is_production and cors_origins == "*":
        print("[WARNING] CORS_ORIGINS is set to '*' which allows all origins. Restrict this in production!")
    CORS(
        app,
        resources={r"/*": {"origins": [o.strip() for o in cors_origins.split(",") if o.strip()]}},
        supports_credentials=False,
        allow_headers=["Content-Type", "Authorization"],
        expose_headers=["Content-Type"],
    )

    # Basic security headers
    @app.after_request
    def add_security_headers(resp: Response):  # type: ignore[override]
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        csp = os.getenv("CONTENT_SECURITY_POLICY", "default-src 'self' 'unsafe-inline' data: blob:; connect-src *; img-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        resp.headers.setdefault("Content-Security-Policy", csp)
        return resp

    # Resolve project root to serve frontend assets
    project_root = os.path.abspath(os.path.dirname(__file__))

    database_url: Optional[str] = os.getenv("DATABASE_URL")
    sqlite_path = os.path.join(os.path.dirname(__file__), "dsr.sqlite3")
    # Ensure database_url is always a valid non-empty string
    if not database_url or (isinstance(database_url, str) and not database_url.strip()):
        database_url = f"sqlite:///{sqlite_path}"
        print("[backend] DATABASE_URL not set. Using SQLite at:", sqlite_path)

    # Create engine with graceful fallback to SQLite if the configured DB is unreachable
    def create_engine_with_fallback(url: str):
        eng = create_engine(url, pool_pre_ping=True)
        try:
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return eng
        except Exception as exc:
            print("[backend] Primary DATABASE_URL connection failed:", str(exc))
            print("[backend] Falling back to SQLite at:", sqlite_path)
            return create_engine(f"sqlite:///{sqlite_path}", pool_pre_ping=True)

    engine = create_engine_with_fallback(database_url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    Base = declarative_base()

    class Report(Base):  # type: ignore[name-defined]
        __tablename__ = "reports"

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        report_date: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)  # YYYY-MM-DD
        engineer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        project_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        project_code: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

        travel_time_to_site: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)   # HH:MM
        travel_time_from_site: Mapped[Optional[str]] = mapped_column(String(5), nullable=True) # HH:MM
        onsite_time_in: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)        # HH:MM
        onsite_time_out: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)       # HH:MM

        work_objective: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        outcome: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

        engineer_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        customer_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

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

    class ProjectDef(Base):  # type: ignore[name-defined]
        __tablename__ = "project_defs"

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
        start_date: Mapped[str] = mapped_column(String(64), nullable=False)
        client: Mapped[str] = mapped_column(String(255), nullable=False)
        project_name: Mapped[str] = mapped_column(String(255), nullable=False)
        industry: Mapped[str] = mapped_column(String(64), nullable=False)
        pic: Mapped[str] = mapped_column(String(32), nullable=False)
        location: Mapped[str] = mapped_column(String(255), nullable=False)
        created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    class LoginEvent(Base):  # type: ignore[name-defined]
        __tablename__ = "login_events"

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        username: Mapped[str] = mapped_column(String(255), nullable=False)
        role: Mapped[str] = mapped_column(String(20), nullable=False)
        login_time: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Create tables if they don't exist (after all models declared)
    Base.metadata.create_all(bind=engine)

    def ensure_signature_columns_are_text() -> None:
        dialect = engine.dialect.name
        statements = []
        if dialect == "postgresql":
            statements = [
                "ALTER TABLE reports ALTER COLUMN engineer_signature TYPE TEXT",
                "ALTER TABLE reports ALTER COLUMN customer_signature TYPE TEXT",
            ]
        elif dialect in ("mysql", "mariadb"):
            statements = [
                "ALTER TABLE reports MODIFY engineer_signature LONGTEXT",
                "ALTER TABLE reports MODIFY customer_signature LONGTEXT",
            ]
        else:
            return
        try:
            with engine.begin() as connection:
                for stmt in statements:
                    try:
                        connection.execute(text(stmt))
                    except Exception as exc:  # noqa: BLE001
                        message = str(exc).lower()
                        if any(keyword in message for keyword in ("does not exist", "unknown column", "no such column")):
                            continue
                        if any(keyword in message for keyword in ("type text", "longtext", "data type text")):
                            continue
                        print(f"[backend] Warning ensuring signature column type: {exc}")
        except Exception as exc:  # noqa: BLE001
            print(f"[backend] Could not ensure signature columns are TEXT: {exc}")

    ensure_signature_columns_are_text()

    def get_db_session() -> Session:
        return SessionLocal()

    # Initialize default engineer users if they don't exist
    def init_default_users():
        """Create default engineer users on startup"""
        default_engineers = {
            'EN001': 'JKC',
            'EN002': 'RRM',
            'EN003': 'VRG',
            'EN004': 'JRM',
            'EN005': 'RRP',
            'EN007': 'RDB',
            'EN008': 'ASO',
            'EN009': 'AMM',
            'EN010': 'MLL',
            'EN011': 'PHC'
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

    def seed_projectdefs():
        db = get_db_session()
        try:
            existing = db.execute(select(ProjectDef).limit(1)).scalar_one_or_none()
            if existing is not None:
                return
            rows = [
                {
                    "code": "PC230306",
                    "start_date": "February 27, 2024",
                    "client": "CMR Philippines Inc.",
                    "project_name": "NCC Raw Mill Integration Support",
                    "industry": "Cement",
                    "pic": "RRM",
                    "location": "Sison, Pangasinan",
                },
                {
                    "code": "PC230902",
                    "start_date": "February 27, 2024",
                    "client": "CMR Philippines Inc.",
                    "project_name": "Conny PCS7 Support (Singapore)",
                    "industry": "Semiconductor",
                    "pic": "RRM",
                    "location": "Singapore",
                },
                {
                    "code": "PC231101",
                    "start_date": "February 27, 2024",
                    "client": "CMR Philippines Inc.",
                    "project_name": "BESS Projects Support (Gamu / Lumban / Mexico)",
                    "industry": "Power",
                    "pic": "RRM",
                    "location": "Isabela / Laguna / Pampanga",
                },
                {
                    "code": "PC240102",
                    "start_date": "February 27, 2024",
                    "client": "CMR Philippines, Inc.",
                    "project_name": "BESS Mexico 3 SAS",
                    "industry": "Power",
                    "pic": "RRM",
                    "location": "Pampanga",
                },
                {
                    "code": "PC240103",
                    "start_date": "February 1, 2024",
                    "client": "CMR Philippines, Inc.",
                    "project_name": "CMRFE Engineering Support",
                    "industry": "Oil & Gas",
                    "pic": "RRM",
                    "location": "Singapore",
                },
            ]
            for r in rows:
                db.add(ProjectDef(**r))
            db.commit()
            print("[backend] Seeded project_defs table")
        except Exception as e:
            print("[backend] Failed to seed project_defs:", e)
            db.rollback()
        finally:
            db.close()

    seed_projectdefs()

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

    @app.get("/favicon.ico")
    def favicon():  # type: ignore[no-untyped-def]
        # Serve a small inline SVG as a fallback if no file exists
        icon_path = os.path.join(project_root, "favicon.ico")
        if os.path.exists(icon_path):
            return send_from_directory(project_root, "favicon.ico")
        svg = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>\n  <rect width='16' height='16' fill='black'/>\n  <text x='8' y='12' text-anchor='middle' font-size='12' fill='white'>X</text>\n</svg>"""
        return Response(svg, mimetype="image/svg+xml")

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

    @app.get("/projects.html")
    def projects_html():  # type: ignore[no-untyped-def]
        return send_from_directory(project_root, "projects.html")


    def create_reset_token() -> str:
        return secrets.token_urlsafe(32)

    def create_jwt(user: "User") -> str:
        try:
            payload = {
                "sub": str(user.id),
                "username": user.username,
                "role": user.role,
                "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=jwt_expire_minutes),
                "iat": datetime.now(tz=timezone.utc),
            }
            print(f"[JWT] Creating token for user: {user.username}, secret length: {len(jwt_secret) if jwt_secret else 0}")
            
            # PyJWT 2.x returns string directly, but handle both cases
            token_result = jwt.encode(payload, jwt_secret, algorithm="HS256")
            
            # Ensure we return a string, not bytes
            if isinstance(token_result, bytes):
                token = token_result.decode('utf-8')
            else:
                token = str(token_result)
            
            print(f"[JWT] Token created successfully, type: {type(token)}, length: {len(token)}")
            return token
        except Exception as jwt_error:
            print(f"[JWT] Error creating token: {jwt_error}")
            import traceback
            print(f"[JWT] Traceback: {traceback.format_exc()}")
            raise

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

    def normalize_signature_value(raw_value: Any) -> str:
        """Validate and normalize base64 signature data URIs."""
        if not isinstance(raw_value, str):
            return ""
        value = raw_value.strip()
        if not value:
            return ""
        if value.startswith("data:image"):
            try:
                _, data_part = value.split(",", 1)
            except ValueError:
                print("[backend] Invalid signature payload (missing comma separator)")
                return ""
            if len(data_part) > 2_000_000:
                print("[backend] Signature payload too large; ignoring")
                return ""
            try:
                import base64
                base64.b64decode(data_part, validate=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[backend] Invalid signature payload; base64 decode failed: {exc}")
                return ""
            return value
        return value

    # Error handler to return JSON instead of HTML for API routes
    @app.errorhandler(500)
    def handle_500_error(e):
        import traceback
        error_traceback = traceback.format_exc()
        print(f"\n[ERROR HANDLER] ===== 500 ERROR =====")
        print(f"[ERROR HANDLER] Error: {e}")
        print(f"[ERROR HANDLER] Traceback:\n{error_traceback}")
        print(f"[ERROR HANDLER] =======================\n")
        
        # Check if this is an API request (JSON expected)
        if request.path.startswith('/auth/') or request.path.startswith('/api/'):
            return jsonify({"ok": False, "error": "Internal server error"}), 500
        # Otherwise return Flask's default error page (don't re-raise)
        from werkzeug.exceptions import InternalServerError
        return InternalServerError().get_response()

    @app.route("/auth/login", methods=["POST", "OPTIONS"])
    def auth_login():  # type: ignore[no-untyped-def]
        if request.method == "OPTIONS":
            return ("", 204)
        
        print(f"[LOGIN] === STARTING LOGIN REQUEST ===")
        print(f"[LOGIN] Method: {request.method}")
        print(f"[LOGIN] Content-Type: {request.content_type}")
        print(f"[LOGIN] Content-Length: {request.content_length}")
        
        try:
            # Try to get JSON payload
            if not request.is_json:
                print(f"[LOGIN] Request is not JSON, content-type: {request.content_type}")
                payload = request.get_json(force=True, silent=True)
            else:
                payload = request.get_json(force=False, silent=True)
            
            if payload is None:
                print(f"[LOGIN] Failed to parse JSON")
                try:
                    raw_data = request.get_data(as_text=True)
                    print(f"[LOGIN] Raw request data: {raw_data[:200]}")
                except:
                    pass
                return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
            
            print(f"[LOGIN] Successfully parsed JSON payload")
        except Exception as e:
            print(f"[LOGIN] Error parsing JSON: {e}")
            import traceback
            print(f"[LOGIN] Traceback: {traceback.format_exc()}")
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        username = (payload or {}).get("username", "").strip()
        password = (payload or {}).get("password", "")
        
        print(f"[LOGIN] Login attempt for username: '{username}' (length: {len(username)})")
        print(f"[LOGIN] Password provided: {'yes' if password else 'no'} (length: {len(password)})")
        
        if not username or not password:
            print(f"[LOGIN] Missing username or password")
            return jsonify({"ok": False, "error": "Username and password are required"}), 400

        db: Session = get_db_session()
        try:
            # Normalize username - lowercase for admin, uppercase for engineers
            if username.lower() == "admin":
                search_username = "admin"  # Always lowercase for admin
            elif username.upper().startswith("EN"):
                search_username = username.upper()  # Uppercase for engineers
            else:
                search_username = username  # Keep as-is for others
            
            print(f"[LOGIN] Searching for username: '{search_username}'")
            
            user = db.execute(select(User).where(User.username == search_username)).scalar_one_or_none()
            if user is None:
                print(f"[LOGIN] User not found: '{search_username}'")
                return jsonify({"ok": False, "error": "Invalid username or password"}), 401
            
            print(f"[LOGIN] User found: {user.username} (role: {user.role})")
            
            password_valid = check_password_hash(user.password_hash, password)
            if not password_valid:
                print(f"[LOGIN] Invalid password for user: {user.username}")
                return jsonify({"ok": False, "error": "Invalid username or password"}), 401
            
            print(f"[LOGIN] Password valid for user: {user.username} ({user.role})")
            
            # Verify user has an ID before creating JWT
            if not user.id:
                print(f"[LOGIN] ERROR: User {user.username} has no ID!")
                return jsonify({"ok": False, "error": "User data error"}), 500
            
            print(f"[LOGIN] User ID: {user.id}")
            
            try:
                print(f"[LOGIN] Creating JWT token...")
                token = create_jwt(user)
                if isinstance(token, bytes):
                    token = token.decode('utf-8')
                print(f"[LOGIN] JWT token created successfully, length: {len(token)}")
            except Exception as jwt_error:
                print(f"[LOGIN] Error creating JWT token: {jwt_error}")
                import traceback
                print(f"[LOGIN] JWT Error Traceback:\n{traceback.format_exc()}")
                return jsonify({"ok": False, "error": f"Token generation failed: {str(jwt_error)}"}), 500
            
            # Log the login event for admin notifications (use separate session to avoid conflicts)
            login_db: Session = get_db_session()
            try:
                # Table should already exist from startup initialization
                login_event = LoginEvent(
                    username=user.username,
                    role=user.role,
                    login_time=datetime.now(timezone.utc)
                )
                login_db.add(login_event)
                login_db.commit()
                print(f"[LOGIN EVENT] OK Successfully logged login: {user.username} ({user.role})")
            except Exception as login_event_error:
                # Log error but don't fail the login
                print(f"[LOGIN EVENT ERROR] Failed to log login event: {login_event_error}")
                login_db.rollback()
            finally:
                login_db.close()
            
            print(f"[LOGIN] Login successful for {username}")
            return jsonify({"ok": True, "token": token, "user": {"username": user.username, "role": user.role}}), 200
        except Exception as e:
            print(f"[LOGIN] Unexpected error: {e}")
            import traceback
            error_traceback = traceback.format_exc()
            print(f"[LOGIN] Traceback:\n{error_traceback}")
            return jsonify({"ok": False, "error": f"Internal server error: {str(e)}"}), 500
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

    # Project definitions API
    @app.get("/projectdefs")
    def list_projectdefs():  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        db = get_db_session()
        try:
            rows = db.execute(select(ProjectDef).order_by(ProjectDef.created_at.desc())).scalars().all()
            items = [
                {
                    "code": r.code,
                    "startDate": r.start_date,
                    "client": r.client,
                    "name": r.project_name,
                    "industry": r.industry,
                    "pic": r.pic,
                    "location": r.location,
                }
                for r in rows
            ]
            return jsonify({"ok": True, "items": items}), 200
        finally:
            db.close()

    @app.post("/projectdefs")
    def create_projectdef():  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        required = ["code", "startDate", "client", "name", "industry", "pic", "location"]
        missing = [f for f in required if not (payload or {}).get(f)]
        if missing:
            return jsonify({"ok": False, "error": "Missing fields", "fields": missing}), 400
        db = get_db_session()
        try:
            exists = db.execute(select(ProjectDef).where(ProjectDef.code == payload["code"]))\
                .scalar_one_or_none()
            if exists is not None:
                return jsonify({"ok": False, "error": "Project code already exists"}), 400
            row = ProjectDef(
                code=payload["code"],
                start_date=payload["startDate"],
                client=payload["client"],
                project_name=payload["name"],
                industry=payload["industry"],
                pic=payload["pic"],
                location=payload["location"],
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True}), 201
        finally:
            db.close()

    @app.put("/projectdefs/<string:code>")
    def update_projectdef(code: str):  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        required = ["startDate", "client", "name", "industry", "pic", "location"]
        missing = [f for f in required if not (payload or {}).get(f)]
        if missing:
            return jsonify({"ok": False, "error": "Missing fields", "fields": missing}), 400
        db = get_db_session()
        try:
            project = db.execute(select(ProjectDef).where(ProjectDef.code == code))\
                .scalar_one_or_none()
            if project is None:
                return jsonify({"ok": False, "error": "Project not found"}), 404
            # Update project fields (code cannot be changed)
            project.start_date = payload["startDate"]
            project.client = payload["client"]
            project.project_name = payload["name"]
            project.industry = payload["industry"]
            project.pic = payload["pic"]
            project.location = payload["location"]
            db.commit()
            return jsonify({"ok": True}), 200
        finally:
            db.close()

    @app.delete("/projectdefs/<string:code>")
    def delete_projectdef(code: str):  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        db = get_db_session()
        try:
            project = db.execute(select(ProjectDef).where(ProjectDef.code == code))\
                .scalar_one_or_none()
            if project is None:
                return jsonify({"ok": False, "error": "Project not found"}), 404
            db.delete(project)
            db.commit()
            print(f"[DELETE PROJECT] Successfully deleted project: {code}")
            return jsonify({"ok": True, "message": "Project deleted successfully"}), 200
        except Exception as e:  # noqa: BLE001
            db.rollback()
            print(f"[DELETE PROJECT] Error deleting project {code}: {e}")
            return jsonify({"ok": False, "error": f"Failed to delete project: {str(e)}"}), 500
        finally:
            db.close()

    @app.post("/submit_report")
    def submit_report():  # type: ignore[no-untyped-def]
        # Check if user is authenticated (always try to get user info)
        user = get_user_from_token()
        
        # Optional auth requirement
        require_auth = os.getenv("SUBMISSION_REQUIRE_AUTH", "false").lower() == "true"
        if require_auth and not user:
            return jsonify({"ok": False, "error": "Authentication required"}), 401
        
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        # No required fields - all are optional now
        # Validate time formats only if provided
        time_fields = {
            "travelTimeToSite": payload.get("travelTimeToSite"),
            "travelTimeFromSite": payload.get("travelTimeFromSite"),
            "onSiteTimeIn": payload.get("onSiteTimeIn"),
            "onSiteTimeOut": payload.get("onSiteTimeOut"),
        }
        for field_name, field_value in time_fields.items():
            if field_value and not validate_time_format(field_value):
                return jsonify({"ok": False, "error": f"Invalid time format for {field_name}. Expected HH:MM (00:00-23:59)"}), 400

        # If user is authenticated, use their username as engineer_name for consistent filtering
        engineer_name = payload.get("engineerName", "")
        if user and user.get("username"):
            # Store as "username (original name)" so we can filter by username but keep the original info
            original_name = payload.get("engineerName", "")
            engineer_name = f"{user.get('username')} - {original_name}" if original_name else user.get('username')
            print(f"[DEBUG] Saving report for authenticated user: '{engineer_name}'")
        else:
            print(f"[DEBUG] Saving report for unauthenticated submission: '{engineer_name}'")

        engineer_signature_value = normalize_signature_value(payload.get("engineerSignature"))
        customer_signature_value = normalize_signature_value(payload.get("customerSignature"))

        new_report = Report(
            report_date=payload.get("reportDate", ""),
            engineer_name=engineer_name or "",
            project_name=payload.get("projectName", ""),
            project_code=payload.get("projectCode", ""),
            travel_time_to_site=payload.get("travelTimeToSite", ""),
            travel_time_from_site=payload.get("travelTimeFromSite", ""),
            onsite_time_in=payload.get("onSiteTimeIn", ""),
            onsite_time_out=payload.get("onSiteTimeOut", ""),
            work_objective=payload.get("workObjective", ""),
            description=payload.get("description", ""),
            outcome=payload.get("outcome", ""),
            engineer_signature=engineer_signature_value,
            customer_signature=customer_signature_value,
        )

        if engineer_signature_value:
            print(f"[SIGNATURE] Engineer signature captured ({len(engineer_signature_value)} chars)")
        if customer_signature_value:
            print(f"[SIGNATURE] Customer signature captured ({len(customer_signature_value)} chars)")

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
        if not user:
            return jsonify({"ok": False, "error": "Authentication required"}), 401

        engineer = (request.args.get("engineer") or "").strip()
        project_code = (request.args.get("project_code") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        q = (request.args.get("q") or "").strip()

        db: Session = get_db_session()
        try:
            stmt = select(Report)
            
            # If user is not admin (i.e., is a client/engineer), only show their own reports
            if user.get("role") != "admin":
                # Filter by username - engineers see only their own reports
                username = user.get('username')
                print(f"[DEBUG] Non-admin user '{username}' fetching their reports")
                stmt = stmt.where(Report.engineer_name.ilike(f"%{username}%"))
            else:
                # Admins can filter by any engineer
                print(f"[DEBUG] Admin user fetching reports")
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
            
            print(f"[DEBUG] Found {len(rows)} reports")
            if rows:
                print(f"[DEBUG] Sample engineer names: {[r.engineer_name for r in rows[:3]]}")

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
        if not user:
            return jsonify({"ok": False, "error": "Authentication required"}), 401

        db: Session = get_db_session()
        try:
            r = db.execute(select(Report).where(Report.id == report_id)).scalar_one_or_none()
            if r is None:
                return jsonify({"ok": False, "error": "Not found"}), 404
            
            # If user is not admin, check if they own this report
            if user.get("role") != "admin":
                if not r.engineer_name or user.get('username', '').lower() not in r.engineer_name.lower():
                    return jsonify({"ok": False, "error": "Forbidden"}), 403
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

    @app.delete("/reports/<int:report_id>")
    def delete_report(report_id: int):  # type: ignore[no-untyped-def]
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Admin access required"}), 403

        db: Session = get_db_session()
        try:
            r = db.execute(select(Report).where(Report.id == report_id)).scalar_one_or_none()
            if r is None:
                return jsonify({"ok": False, "error": "Report not found"}), 404
            
            db.delete(r)
            db.commit()
            return jsonify({"ok": True, "message": "Report deleted successfully"}), 200
        except Exception as exc:
            db.rollback()
            return jsonify({"ok": False, "error": "Database error", "detail": str(exc)}), 500
        finally:
            db.close()

    @app.get("/api/notifications")
    def get_notifications():  # type: ignore[no-untyped-def]
        """Get recent login events and report submissions for admin notifications"""
        print(f"[NOTIFICATIONS API] Request received from: {request.remote_addr}")
        user = get_user_from_token()
        print(f"[NOTIFICATIONS API] User from token: {user}")
        if not user or user.get("role") != "admin":
            print(f"[NOTIFICATIONS API] Access denied - user: {user}, role: {user.get('role') if user else 'None'}")
            return jsonify({"ok": False, "error": "Admin access required"}), 403
        print(f"[NOTIFICATIONS API] Access granted for admin: {user.get('username')}")

        since = request.args.get("since", "")
        
        db: Session = get_db_session()
        try:
            notifications = []
            
            # Get login events - with proper error handling
            try:
                # Ensure login_events table exists
                try:
                    db.execute(text("SELECT 1 FROM login_events LIMIT 1"))
                except Exception:
                    # Table doesn't exist, create it
                    print("[NOTIFICATIONS API] login_events table doesn't exist, creating it...")
                    Base.metadata.create_all(engine, tables=[LoginEvent.__table__])
                    db.commit()
                    print("[NOTIFICATIONS API] login_events table created")
                
                if since:
                    try:
                        # Parse ISO timestamp and ensure it's timezone-aware (UTC)
                        since_time = datetime.fromisoformat(since.replace('Z', '+00:00'))
                        # If the parsed time is naive, assume UTC
                        if since_time.tzinfo is None:
                            since_time = since_time.replace(tzinfo=timezone.utc)
                            
                        login_stmt = select(LoginEvent).where(LoginEvent.login_time >= since_time).order_by(LoginEvent.login_time.desc()).limit(100)
                        print(f"[NOTIFICATIONS API] Fetching login events since: {since_time.isoformat()}")
                    except Exception as e:
                        print(f"[NOTIFICATIONS API] Error parsing 'since' parameter: {e}, fetching all recent events")
                        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
                        login_stmt = select(LoginEvent).where(LoginEvent.login_time > seven_days_ago).order_by(LoginEvent.login_time.desc()).limit(100)
                else:
                    # On initial load (loadAll=true), fetch recent login events (last 30 days, max 500)
                    # This ensures admin sees recent logins without overwhelming the system
                    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
                    login_stmt = select(LoginEvent).where(LoginEvent.login_time >= thirty_days_ago).order_by(LoginEvent.login_time.desc()).limit(500)
                    print(f"[NOTIFICATIONS API] Fetching recent login events (last 30 days, max 500)")
                
                login_events = db.execute(login_stmt).scalars().all()
                print(f"[NOTIFICATIONS API] Found {len(login_events)} login events in database")
                if len(login_events) > 0:
                    print(f"[NOTIFICATIONS API] Most recent login: {login_events[0].username} ({login_events[0].role}) at {login_events[0].login_time.isoformat()}")
                    if len(login_events) > 1:
                        print(f"[NOTIFICATIONS API] Oldest login in results: {login_events[-1].username} at {login_events[-1].login_time.isoformat()}")
                else:
                    print(f"[NOTIFICATIONS API] WARNING: No login events found in database!")
                
                for event in login_events:
                    role_label = "Engineer" if event.role == "client" else event.role.title()
                    notifications.append({
                        "id": f"login-{event.id}",
                        "type": "login",
                        "message": f"{event.username} ({role_label}) logged in",
                        "time": event.login_time.isoformat(),
                        "username": event.username,
                        "role": event.role
                    })
            except Exception as login_error:
                print(f"[NOTIFICATIONS API] Error fetching login events: {login_error}")
                import traceback
                print(f"[NOTIFICATIONS API] Traceback: {traceback.format_exc()}")
                # Continue with empty list instead of failing completely
            
            # Get report submissions - with proper error handling
            try:
                if since:
                    try:
                        # Parse ISO timestamp and ensure it's timezone-aware (UTC)
                        since_time = datetime.fromisoformat(since.replace('Z', '+00:00'))
                        # If the parsed time is naive, assume UTC
                        if since_time.tzinfo is None:
                            since_time = since_time.replace(tzinfo=timezone.utc)
                            
                        report_stmt = select(Report).where(Report.created_at >= since_time).order_by(Report.created_at.desc()).limit(100)
                    except Exception:
                        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
                        report_stmt = select(Report).where(Report.created_at > seven_days_ago).order_by(Report.created_at.desc()).limit(100)
                else:
                    # On initial load (loadAll=true), fetch recent reports (last 30 days, max 500)
                    # This ensures admin sees recent reports without overwhelming the system
                    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
                    report_stmt = select(Report).where(Report.created_at >= thirty_days_ago).order_by(Report.created_at.desc()).limit(500)
                    print(f"[NOTIFICATIONS API] Fetching recent reports (last 30 days, max 500)")
                
                reports = db.execute(report_stmt).scalars().all()
                print(f"[NOTIFICATIONS API] Found {len(reports)} report submissions in database")
                if len(reports) > 0:
                    print(f"[NOTIFICATIONS API] Most recent report: ID {reports[0].id} by {reports[0].engineer_name} at {reports[0].created_at.isoformat()}")
                else:
                    print(f"[NOTIFICATIONS API] WARNING: No reports found in database!")
                
                for report in reports:
                    engineer_name = report.engineer_name or "Unknown"
                    # Extract just the engineer name if it contains " - " (from authenticated submissions)
                    if " - " in engineer_name:
                        parts = engineer_name.split(" - ", 1)
                        engineer_name = parts[1] if len(parts) > 1 and parts[1] else parts[0]
                    
                    project_info = ""
                    if report.project_code:
                        project_info = f" - {report.project_code}"
                    if report.project_name:
                        project_info += f": {report.project_name[:30]}" + ("..." if len(report.project_name) > 30 else "")
                    
                    notifications.append({
                        "id": f"report-{report.id}",
                        "type": "report",
                        "message": f"Report submitted by {engineer_name}{project_info}",
                        "time": report.created_at.isoformat(),
                        "reportId": report.id,
                        "engineerName": engineer_name
                    })
            except Exception as report_error:
                print(f"[NOTIFICATIONS API] Error fetching reports: {report_error}")
                import traceback
                print(f"[NOTIFICATIONS API] Traceback: {traceback.format_exc()}")
                # Continue with empty list instead of failing completely
            
            # Sort by time (most recent first)
            notifications.sort(key=lambda x: x["time"], reverse=True)
            
            print(f"[NOTIFICATIONS API] Returning {len(notifications)} total notifications")
            return jsonify({"ok": True, "notifications": notifications}), 200
        except Exception as api_error:
            print(f"[NOTIFICATIONS API] ✗ FATAL ERROR in notification API: {api_error}")
            import traceback
            print(f"[NOTIFICATIONS API] Fatal error traceback:\n{traceback.format_exc()}")
            return jsonify({"ok": False, "error": "Internal server error", "detail": str(api_error)}), 500
        finally:
            try:
                db.close()
                print(f"[NOTIFICATIONS API] Database session closed")
            except Exception as close_error:
                print(f"[NOTIFICATIONS API] Error closing database session: {close_error}")


    return app


if __name__ == "__main__":
    app = create_app()
    # Force network access - explicitly use 0.0.0.0
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port_value = os.getenv("FLASK_PORT") or os.getenv("PORT") or "5000"
    port = int(port_value)
    # Default to False in production, True in development
    debug_env = os.getenv("FLASK_DEBUG", "").lower()
    if debug_env == "":
        # Auto-detect: if PORT is set (common in production), assume production
        debug = not bool(os.getenv("PORT")) and os.getenv("FLASK_ENV") != "production"
    else:
        debug = debug_env == "true"
    print("\n" + "="*60)
    print("SERVER ACCESSIBLE FROM YOUR NETWORK!")
    print(f"Local URL: http://127.0.0.1:{port}")
    print(f"Network URL: http://{host}:{port}")
    print("="*60 + "\n")
    app.run(host=host, port=port, debug=debug)


