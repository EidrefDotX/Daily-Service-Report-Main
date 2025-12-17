import os
import re
import json
import logging
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Any, Dict

from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]
from flask import Flask, jsonify, request, send_from_directory, Response, g  # pyright: ignore[reportMissingImports]
from flask_cors import CORS  # pyright: ignore[reportMissingModuleSource]
from flask_limiter import Limiter  # pyright: ignore[reportMissingImports]
from flask_limiter.util import get_remote_address  # pyright: ignore[reportMissingImports]
from flask_compress import Compress  # pyright: ignore[reportMissingImports]
from sqlalchemy import Integer, String, Text, DateTime, Boolean, create_engine, select, text, Index, func  # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import declarative_base, sessionmaker, Session, Mapped, mapped_column  # pyright: ignore[reportMissingImports]
from werkzeug.security import generate_password_hash, check_password_hash  # pyright: ignore[reportMissingImports]
import jwt  # pyright: ignore[reportMissingImports]
import secrets


# Load environment from working directory and explicitly from backend/.env for robustness
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


def create_app() -> Flask:
    app = Flask(__name__)
    
    # Performance optimizations
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 300  # Cache static files for 5 minutes
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False  # Faster JSON serialization
    app.config['JSON_SORT_KEYS'] = False  # Skip sorting for faster JSON
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size
    
    # Setup logging
    log_level = logging.INFO if os.getenv("FLASK_ENV", "").lower() == "production" else logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
        ]
    )

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

    # Initialize rate limiter with Redis support
    redis_url = os.getenv("REDIS_URL")
    if redis_url and is_production:
        storage_uri = redis_url
    else:
        storage_uri = "memory://"
    
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=storage_uri,
        headers_enabled=True,
        strategy="fixed-window"  # More predictable than moving-window
    )
    
    # Initialize response compression
    Compress(app)
    
    # Request logging middleware for security auditing
    security_logger = logging.getLogger('security')
    
    @app.before_request
    def add_request_id():
        """Add unique request ID for tracking"""
        g.request_id = str(uuid.uuid4())[:8]
    
    @app.before_request
    def check_ip_access():
        """Check IP whitelist/blacklist"""
        if request.path in ['/health', '/favicon.ico', '/sw.js', '/service-worker.js']:
            return None
        
        client_ip = request.remote_addr
        allowed_ips = [ip.strip() for ip in os.getenv("ALLOWED_IPS", "").split(",") if ip.strip()]
        blocked_ips = [ip.strip() for ip in os.getenv("BLOCKED_IPS", "").split(",") if ip.strip()]
        
        if blocked_ips and client_ip in blocked_ips:
            security_logger.warning(f"Blocked IP attempted access: {client_ip} - Path: {request.path}")
            return jsonify({"ok": False, "error": "Access denied"}), 403
        
        if allowed_ips and is_production:
            if client_ip not in allowed_ips:
                security_logger.warning(f"Unauthorized IP attempted access: {client_ip} - Path: {request.path}")
                return jsonify({"ok": False, "error": "Access denied"}), 403
        
        return None
    
    @app.before_request
    def log_request_info():
        """Enhanced request logging with request ID"""
        if request.path not in ['/health', '/favicon.ico', '/sw.js', '/service-worker.js']:
            request_id = getattr(g, 'request_id', 'unknown')
            security_logger.info(
                f"REQ[{request_id}] {request.method} {request.path} - "
                f"IP: {request.remote_addr} - "
                f"User-Agent: {request.headers.get('User-Agent', 'Unknown')[:100]} - "
                f"Referer: {request.headers.get('Referer', 'None')[:100]}"
            )
    
    @app.after_request
    def log_response_info(resp: Response):  # type: ignore[override]
        """Log response status for monitoring"""
        if request.path not in ['/health', '/favicon.ico', '/sw.js', '/service-worker.js']:
            if resp.status_code >= 400:
                security_logger.warning(f"{request.method} {request.path} - Status: {resp.status_code} - IP: {request.remote_addr}")
        return resp
    
    # Enhanced security headers with performance optimizations
    @app.after_request
    def add_security_headers(resp: Response):  # type: ignore[override]
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("X-XSS-Protection", "1; mode=block")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        
        # Add request ID for tracking
        resp.headers.setdefault("X-Request-ID", getattr(g, 'request_id', 'unknown'))
        
        # Add HSTS in production only
        if is_production:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        
        # Enhanced CSP - allow cdnjs for XLSX library
        csp = os.getenv("CONTENT_SECURITY_POLICY", 
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' *; font-src 'self' data:;")
        resp.headers.setdefault("Content-Security-Policy", csp)
        
        # Performance headers - keep connections alive for faster subsequent requests
        resp.headers.setdefault("Connection", "keep-alive")
        return resp
    
    # Global error handler with secure error messages
    @app.errorhandler(Exception)
    def handle_exception(e):  # type: ignore[misc]
        """Global error handler with secure error messages"""
        error_logger = logging.getLogger('error')
        error_logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        
        if is_production:
            # Don't expose internal errors in production
            return jsonify({"ok": False, "error": "An internal error occurred. Please try again later."}), 500
        else:
            # Show details in development
            return jsonify({
                "ok": False, 
                "error": str(e),
                "traceback": traceback.format_exc()
            }), 500

    # Resolve project root to serve frontend assets
    project_root = os.path.abspath(os.path.dirname(__file__))

    database_url: Optional[str] = os.getenv("DATABASE_URL")
    sqlite_path = os.path.join(os.path.dirname(__file__), "dsr.sqlite3")
    
    # Production: Require PostgreSQL, fail if DATABASE_URL is missing
    if is_production:
        if not database_url or (isinstance(database_url, str) and not database_url.strip()):
            raise ValueError(
                "DATABASE_URL environment variable must be set in production. "
                "SQLite is not supported in production environments. "
                "Please configure a PostgreSQL database (Neon, Supabase, etc.) and set DATABASE_URL."
            )
        # Validate it's a PostgreSQL connection (not SQLite)
        if database_url.startswith("sqlite"):
            raise ValueError(
                "SQLite is not supported in production. "
                "Please use PostgreSQL. Set DATABASE_URL to a PostgreSQL connection string."
            )
        print("[backend] Production mode: Using PostgreSQL from DATABASE_URL")
    
    # Development: Fallback to SQLite if DATABASE_URL is not set
    if not is_production:
        if not database_url or (isinstance(database_url, str) and not database_url.strip()):
            database_url = f"sqlite:///{sqlite_path}"
            print("[backend] DATABASE_URL not set. Using SQLite for local development at:", sqlite_path)

    # Ensure database_url is a string at this point (type narrowing for type checker)
    if not database_url:
        # This should never happen due to logic above, but satisfy type checker
        database_url = f"sqlite:///{sqlite_path}"
        print("[backend] Fallback: Using SQLite for local development at:", sqlite_path)

    # Create engine with different behavior for production vs development
    def create_engine_with_fallback(url: str):
        # Configure SQLite-specific settings for better concurrency
        if url.startswith("sqlite"):
            from sqlalchemy.pool import NullPool
            # SQLite connection args for better concurrency and timeout handling
            connect_args = {
                "check_same_thread": False,  # Allow multi-threaded access
                "timeout": 60.0,  # 60 second timeout for database operations (increased for better concurrency)
            }
            # Use NullPool for SQLite - creates new connection per request
            # This works much better with WAL mode than StaticPool (single connection)
            # NullPool prevents connection pool locking issues
            eng = create_engine(
                url,
                poolclass=NullPool,  # Changed from StaticPool - better for WAL mode
                connect_args=connect_args,
                pool_pre_ping=False,  # Not needed with NullPool
            )
            # Enable WAL mode for better concurrency (Write-Ahead Logging)
            # Note: WAL mode will be set on each session in get_db_session()
            try:
                with eng.connect() as conn:
                    conn.execute(text("PRAGMA journal_mode=WAL"))
                    conn.execute(text("PRAGMA synchronous=NORMAL"))
                    conn.execute(text("PRAGMA busy_timeout=60000"))  # 60 second busy timeout for better concurrency
                    conn.execute(text("PRAGMA cache_size=-64000"))  # 64MB cache for better performance
                    conn.execute(text("PRAGMA temp_store=memory"))  # Use memory for temp tables
                    conn.commit()
                    print("[backend] SQLite WAL mode enabled with NullPool for better concurrency")
            except Exception as wal_error:
                print(f"[backend] Warning: Could not enable WAL mode: {wal_error}")
        else:
            # PostgreSQL or other databases - optimized pool settings for performance
            # Increased pool size for better concurrency, faster timeouts for quick failure detection
            from sqlalchemy.pool import QueuePool
            connect_args = {"connect_timeout": 10, "application_name": "dsr_backend"}
            if "postgresql" in url:
                # PostgreSQL-specific optimizations
                eng = create_engine(
                    url, 
                    poolclass=QueuePool,
                    pool_size=10,  # Increased pool size for better concurrency
                    max_overflow=20,  # Allow up to 20 overflow connections
                    pool_pre_ping=True,  # Verify connections before using
                    pool_timeout=10,  # Connection timeout
                    pool_recycle=3600,  # Recycle connections after 1 hour
                    connect_args=connect_args
                )
            else:
                eng = create_engine(
                    url, 
                    poolclass=QueuePool,
                    pool_size=10,
                    max_overflow=20,
                    pool_pre_ping=True,
                    pool_timeout=10,
                    pool_recycle=3600,
                    connect_args=connect_args
            )
        
        try:
            # Quick connection test with timeout
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            print(f"[backend] Successfully connected to database: {url.split('@')[-1] if '@' in url else 'SQLite'}")
            return eng
        except Exception as exc:
            if is_production:
                # Production: Fail fast - do not fallback to SQLite
                print(f"[backend] FATAL: PostgreSQL connection failed in production: {exc}")
                raise RuntimeError(
                    f"Failed to connect to PostgreSQL database in production. "
                    f"Please check your DATABASE_URL and ensure the database is accessible. "
                    f"Error: {exc}"
                ) from exc
            else:
                # Development: Fallback to SQLite with proper configuration
                print(f"[backend] Primary DATABASE_URL connection failed (expected if PostgreSQL not running): {exc}")
                print("[backend] Falling back to SQLite for local development at:", sqlite_path)
                from sqlalchemy.pool import NullPool
                connect_args = {
                    "check_same_thread": False,
                    "timeout": 60.0,  # Increased timeout for better concurrency
                }
                fallback_eng = create_engine(
                    f"sqlite:///{sqlite_path}",
                    poolclass=NullPool,  # Changed from StaticPool - better for WAL mode
                    connect_args=connect_args,
                    pool_pre_ping=False,  # Not needed with NullPool
                )
                # Enable WAL mode for fallback SQLite
                try:
                    with fallback_eng.connect() as conn:
                        conn.execute(text("PRAGMA journal_mode=WAL"))
                        conn.execute(text("PRAGMA synchronous=NORMAL"))
                        conn.execute(text("PRAGMA busy_timeout=60000"))  # 60 second busy timeout
                        conn.execute(text("PRAGMA cache_size=-64000"))  # 64MB cache
                        conn.execute(text("PRAGMA temp_store=memory"))  # Use memory for temp tables
                        conn.commit()
                        print("[backend] SQLite WAL mode enabled with NullPool for fallback database")
                except Exception as wal_error:
                    print(f"[backend] Warning: Could not enable WAL mode: {wal_error}")
                return fallback_eng

    engine = create_engine_with_fallback(database_url)
    # Optimize sessionmaker for better performance
    # expire_on_commit=False: Objects remain usable after commit (faster for read operations)
    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False  # Keep objects accessible after commit for better performance
    )

    Base = declarative_base()

    class Report(Base):  # type: ignore[name-defined]
        __tablename__ = "reports"
        __table_args__ = (
            Index('idx_report_engineer_name', 'engineer_name'),
            Index('idx_report_date', 'report_date'),
            Index('idx_report_project_code', 'project_code'),
            Index('idx_report_created_at', 'created_at'),
        )

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        report_date: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)  # YYYY-MM-DD
        engineer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        project_phase: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        project_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        project_code: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        client_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        plant_location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

        travel_time_to_site: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)   # HH:MM AM/PM (12-hour format)
        travel_time_from_site: Mapped[Optional[str]] = mapped_column(String(8), nullable=True) # HH:MM AM/PM (12-hour format)
        travel_time_to_home_base: Mapped[Optional[str]] = mapped_column(String(8), nullable=True) # HH:MM AM/PM (12-hour format)
        travel_time_out: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)      # HH:MM AM/PM (12-hour format)
        onsite_time_in: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)        # HH:MM AM/PM (12-hour format)
        onsite_time_out: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)       # HH:MM AM/PM (12-hour format)

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
        password_history: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of last 5 password hashes
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

    class FailedLoginAttempt(Base):  # type: ignore[name-defined]
        __tablename__ = "failed_login_attempts"
        __table_args__ = (
            Index('idx_failed_login_username', 'username'),
            Index('idx_failed_login_ip', 'ip_address'),
            Index('idx_failed_login_time', 'attempt_time'),
        )

        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        username: Mapped[str] = mapped_column(String(255), nullable=False)
        ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
        attempt_time: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Create tables if they don't exist (after all models declared)
    Base.metadata.create_all(bind=engine)

    def ensure_travel_time_columns_exist() -> None:
        """Ensure travel_time_to_home_base and travel_time_out columns exist in reports table, and fix column sizes for time fields"""
        dialect = engine.dialect.name
        try:
            with engine.begin() as connection:
                if dialect == "sqlite":
                    # Check if columns exist using PRAGMA
                    result = connection.execute(text("PRAGMA table_info(reports)"))
                    columns = [row[1] for row in result.fetchall()]
                    
                    if 'travel_time_to_home_base' not in columns:
                        print("[MIGRATION] Adding column: travel_time_to_home_base")
                        try:
                            connection.execute(text("ALTER TABLE reports ADD COLUMN travel_time_to_home_base VARCHAR(8)"))
                        except Exception as col_error:
                            if "duplicate column" not in str(col_error).lower():
                                raise
                    
                    if 'travel_time_out' not in columns:
                        print("[MIGRATION] Adding column: travel_time_out")
                        try:
                            connection.execute(text("ALTER TABLE reports ADD COLUMN travel_time_out VARCHAR(8)"))
                        except Exception as col_error:
                            if "duplicate column" not in str(col_error).lower():
                                raise
                        
                elif dialect == "postgresql":
                    # Check if columns exist
                    result = connection.execute(text("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = 'reports' 
                        AND column_name IN ('travel_time_to_home_base', 'travel_time_out')
                    """))
                    existing_columns = [row[0] for row in result.fetchall()]
                    
                    if 'travel_time_to_home_base' not in existing_columns:
                        print("[MIGRATION] Adding column: travel_time_to_home_base")
                        connection.execute(text("ALTER TABLE reports ADD COLUMN travel_time_to_home_base VARCHAR(8)"))
                    
                    if 'travel_time_out' not in existing_columns:
                        print("[MIGRATION] Adding column: travel_time_out")
                        connection.execute(text("ALTER TABLE reports ADD COLUMN travel_time_out VARCHAR(8)"))
        except Exception as e:
            # Ignore errors if columns already exist or other non-critical issues
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ("duplicate column", "already exists", "no such column")):
                # Column might already exist or table doesn't exist yet (will be created by create_all)
                pass
            else:
                print(f"[MIGRATION] Warning ensuring travel time columns exist: {e}")

    # Run migration to add travel time columns
    ensure_travel_time_columns_exist()

    def ensure_project_info_columns_exist() -> None:
        """Ensure project_phase, client_name, and plant_location columns exist in reports table"""
        dialect = engine.dialect.name
        columns_to_add = {
            'project_phase': String(255),
            'client_name': String(255),
            'plant_location': String(255)
        }
        try:
            with engine.begin() as connection:
                if dialect == "sqlite":
                    result = connection.execute(text("PRAGMA table_info(reports)"))
                    columns = [row[1] for row in result.fetchall()]
                    for col_name, col_type in columns_to_add.items():
                        if col_name not in columns:
                            print(f"[MIGRATION] Adding column (SQLite): {col_name}")
                            connection.execute(text(f"ALTER TABLE reports ADD COLUMN {col_name} VARCHAR(255)"))
                        else:
                            print(f"[MIGRATION] Column {col_name} already exists (SQLite)")
                elif dialect == "postgresql":
                    for col_name, col_type in columns_to_add.items():
                        result = connection.execute(text(f"""
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name = 'reports' AND column_name = '{col_name}'
                        """)).scalar_one_or_none()
                        if result is None:
                            print(f"[MIGRATION] Adding column (PostgreSQL): {col_name}")
                            connection.execute(text(f"ALTER TABLE reports ADD COLUMN {col_name} VARCHAR(255)"))
                        else:
                            print(f"[MIGRATION] Column {col_name} already exists (PostgreSQL)")
        except Exception as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ("duplicate column", "already exists", "no such column")):
                pass
            else:
                print(f"[MIGRATION] Warning ensuring project info columns exist: {e}")

    # Run migration to add project info columns
    ensure_project_info_columns_exist()

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
    
    def ensure_password_history_column_exists() -> None:
        """Ensure password_history column exists in users table"""
        dialect = engine.dialect.name
        try:
            with engine.begin() as connection:
                if dialect == "sqlite":
                    result = connection.execute(text("PRAGMA table_info(users)"))
                    columns = [row[1] for row in result.fetchall()]
                    if 'password_history' not in columns:
                        print("[MIGRATION] Adding column: password_history (SQLite)")
                        connection.execute(text("ALTER TABLE users ADD COLUMN password_history TEXT"))
                elif dialect == "postgresql":
                    result = connection.execute(text("""
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'users' AND column_name = 'password_history'
                    """)).scalar_one_or_none()
                    if result is None:
                        print("[MIGRATION] Adding column: password_history (PostgreSQL)")
                        connection.execute(text("ALTER TABLE users ADD COLUMN password_history TEXT"))
        except Exception as exc:
            error_msg = str(exc).lower()
            if any(keyword in error_msg for keyword in ("duplicate column", "already exists", "no such column")):
                pass
            else:
                print(f"[MIGRATION] Warning ensuring password_history column exists: {exc}")
    
    ensure_password_history_column_exists()

    def get_db_session() -> Session:
        """Get a database session with proper SQLite settings - optimized for speed and concurrency"""
        session = SessionLocal()
        # For SQLite, ensure each session has proper timeout and WAL settings
        # CRITICAL: Set WAL mode and busy_timeout on EVERY session to prevent locking
        if engine.dialect.name == "sqlite":
            try:
                # Set WAL mode and busy_timeout on every session for better concurrency
                # This is essential when using NullPool (new connection per request)
                session.execute(text("PRAGMA journal_mode=WAL"))
                session.execute(text("PRAGMA busy_timeout=60000"))  # 60 seconds for maximum concurrency
                session.execute(text("PRAGMA synchronous=NORMAL"))
                session.execute(text("PRAGMA cache_size=-64000"))  # 64MB cache
                session.execute(text("PRAGMA temp_store=memory"))  # Use memory for temp tables
            except Exception:
                pass  # Ignore if pragma fails (connection may not be ready)
        return session

    # Initialize default engineer users if they don't exist
    def init_default_users():
        """Create default engineer users on startup"""
        # Note: EN006 is intentionally excluded and will not be created
        default_engineers = {
            'EN001': 'JKC',
            'EN002': 'RRM',
            'EN003': 'VRG',
            'EN004': 'JRM',
            'EN005': 'RRP',
            # EN006 is intentionally excluded
            'EN007': 'RDB',
            'EN008': 'ASO',
            'EN009': 'AMM',
            'EN010': 'MLL',
            'EN011': 'PHC'
        }
        default_password = '#DotXsolutions.opc'
        
        db = get_db_session()
        created_count = 0
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
                    created_count += 1
                    print(f"[backend] Created default user: {code} ({name})")
            db.commit()
            if created_count > 0:
                print(f"[backend] Created {created_count} default engineer users")
            else:
                # Verify users exist
                total_users = db.execute(select(func.count(User.id))).scalar() or 0
                print(f"[backend] Default users already exist ({total_users} total users)")
        except Exception as e:
            print(f"[backend] Error creating default users: {e}")
            import traceback
            traceback.print_exc()
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

    # Cache health status to avoid database query on every request
    _health_cache = {"status": "ok", "timestamp": None}
    _health_cache_ttl = 5  # Cache for 5 seconds
    
    @app.get("/health")
    def health() -> Tuple[dict, int]:
        """Fast health check with cached database status"""
        import time
        now = time.time()
        
        # Return cached status if still valid
        if _health_cache["timestamp"] and (now - _health_cache["timestamp"]) < _health_cache_ttl:
            status_code = 200 if _health_cache["status"] == "ok" else 500
            return _health_cache.copy(), status_code
        
        # Check database connection (with quick timeout)
        try:
            # Use pool connection directly instead of opening new connection
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            _health_cache["status"] = "ok"
            _health_cache["timestamp"] = now
            return {"status": "ok"}, 200
        except Exception as exc:  # noqa: BLE001 - report health failure details
            _health_cache["status"] = "error"
            _health_cache["timestamp"] = now
            _health_cache["detail"] = str(exc)
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
        svg = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>\n  <rect width='16' height='16' fill='#0e1111'/>\n  <text x='8' y='12' text-anchor='middle' font-size='12' fill='white'>X</text>\n</svg>"""
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
            
            # PyJWT 2.x returns string directly, but handle both cases
            token_result = jwt.encode(payload, jwt_secret, algorithm="HS256")
            
            # Ensure we return a string, not bytes
            if isinstance(token_result, bytes):
                token = token_result.decode('utf-8')
            else:
                token = str(token_result)
            
            return token
        except Exception as jwt_error:
            print(f"[JWT] Error creating token: {jwt_error}")
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
        """Validate time format is HH:MM AM/PM (12-hour format)"""
        if not time_str or not isinstance(time_str, str):
            return False
        # Accept 12-hour format: HH:MM AM/PM (e.g., "01:30 PM", "12:00 AM")
        pattern = r'^([0]?[1-9]|1[0-2]):([0-5][0-9])\s*(AM|PM)$'
        return bool(re.match(pattern, time_str, re.IGNORECASE))
    
    def convert_24_to_12(time_24: str) -> str:
        """Convert 24-hour format (HH:MM) to 12-hour format (HH:MM AM/PM)"""
        if not time_24 or time_24 == 'N/A' or ':' not in time_24:
            return time_24 or 'N/A'
        try:
            # Handle both 24-hour and already 12-hour formats
            if 'AM' in time_24.upper() or 'PM' in time_24.upper():
                return time_24  # Already in 12-hour format
            parts = time_24.split(':')
            if len(parts) != 2:
                return time_24
            hour = int(parts[0])
            minute = parts[1]
            if hour == 0:
                return f"12:{minute} AM"
            elif hour < 12:
                return f"{hour}:{minute} AM"
            elif hour == 12:
                return f"12:{minute} PM"
            else:
                return f"{hour - 12}:{minute} PM"
        except (ValueError, IndexError):
            return time_24
    
    def convert_12_to_24(time_12: str) -> str:
        """Convert 12-hour format (HH:MM AM/PM) to 24-hour format (HH:MM) for calculations"""
        if not time_12 or time_12 == 'N/A':
            return time_12 or ''
        try:
            # If already in 24-hour format, return as is
            if 'AM' not in time_12.upper() and 'PM' not in time_12.upper():
                # Check if it's valid 24-hour format
                if re.match(r'^([0-1][0-9]|2[0-3]):([0-5][0-9])$', time_12):
                    return time_12
                return time_12
            
            # Parse 12-hour format
            time_12_upper = time_12.upper().strip()
            parts = time_12_upper.replace('AM', '').replace('PM', '').strip().split(':')
            if len(parts) != 2:
                return time_12
            
            hour = int(parts[0])
            minute = parts[1]
            is_pm = 'PM' in time_12_upper
            
            if hour == 12:
                hour_24 = 0 if not is_pm else 12
            else:
                hour_24 = hour if not is_pm else hour + 12
            
            return f"{hour_24:02d}:{minute}"
        except (ValueError, IndexError):
            return time_12

    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username format and length"""
        if not username or not isinstance(username, str):
            return False, "Username is required"
        username = username.strip()
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        if len(username) > 255:
            return False, "Username must be at most 255 characters long"
        # Allow alphanumeric, underscores, hyphens, and dots
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, hyphens, and dots"
        # Prevent SQL injection patterns (extra safety)
        if any(char in username for char in [';', "'", '"', '--', '/*', '*/', 'xp_', 'sp_']):
            return False, "Username contains invalid characters"
        return True, ""

    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """Validate password meets security requirements"""
        if not password or not isinstance(password, str):
            return False, "Password is required"
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if len(password) > 128:
            return False, "Password must be at most 128 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
        return True, ""
    
    def validate_text_field(field_value: Any, field_name: str, max_length: int = 1000, required: bool = False) -> Tuple[bool, str]:
        """Validate text field with length limits and XSS protection"""
        if field_value is None:
            if required:
                return False, f"{field_name} is required"
            return True, ""
        
        if not isinstance(field_value, str):
            return False, f"{field_name} must be a string"
        
        field_value = field_value.strip()
        
        if required and not field_value:
            return False, f"{field_name} is required"
        
        if len(field_value) > max_length:
            return False, f"{field_name} exceeds maximum length of {max_length} characters"
        
        # Check for potentially dangerous XSS patterns
        dangerous_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', 'onmouseover=', 
                            'vbscript:', 'data:text/html', '<iframe', '<object', '<embed']
        field_lower = field_value.lower()
        for pattern in dangerous_patterns:
            if pattern in field_lower:
                return False, f"{field_name} contains invalid content"
        
        return True, ""

    def check_account_locked(username: str, ip_address: str) -> Tuple[bool, Optional[datetime]]:
        """Check if account is locked due to too many failed attempts"""
        db = get_db_session()
        try:
            max_attempts = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
            lockout_minutes = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
            
            # Count failed attempts in last lockout period
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=lockout_minutes)
            failed_count = db.execute(
                select(func.count(FailedLoginAttempt.id))
                .where(FailedLoginAttempt.username == username)
                .where(FailedLoginAttempt.attempt_time >= cutoff)
                .where(FailedLoginAttempt.success == False)
            ).scalar() or 0
            
            # Lock account after max_attempts failed attempts
            if failed_count >= max_attempts:
                # Get lockout expiration (lockout_minutes from first failed attempt)
                first_failed = db.execute(
                    select(FailedLoginAttempt.attempt_time)
                    .where(FailedLoginAttempt.username == username)
                    .where(FailedLoginAttempt.attempt_time >= cutoff)
                    .where(FailedLoginAttempt.success == False)
                    .order_by(FailedLoginAttempt.attempt_time.asc())
                    .limit(1)
                ).scalar()
                
                if first_failed:
                    lockout_until = first_failed + timedelta(minutes=lockout_minutes)
                    if datetime.now(timezone.utc) < lockout_until:
                        return True, lockout_until
            
            return False, None
        finally:
            db.close()
    
    def check_password_history(user: User, new_password: str) -> bool:
        """Check if password was recently used (prevent reuse)"""
        if not user.password_history:
            return True
        
        try:
            history = json.loads(user.password_history)
            for old_hash in history:
                if check_password_hash(old_hash, new_password):
                    return False
        except:
            pass
        return True
    
    def update_password_history(user: User, new_hash: str):
        """Update password history (keep last 5)"""
        history = []
        if user.password_history:
            try:
                history = json.loads(user.password_history)
            except:
                pass
        
        history.append(new_hash)
        history = history[-5:]  # Keep last 5
        
        user.password_history = json.dumps(history)
    
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
    @limiter.limit("5 per minute")  # 5 login attempts per minute to prevent brute force
    def auth_login():  # type: ignore[no-untyped-def]
        if request.method == "OPTIONS":
            return ("", 204)
        
        # Optimized: Reduced logging for faster login
        try:
            # Try to get JSON payload
            if not request.is_json:
                payload = request.get_json(force=True, silent=True)
            else:
                payload = request.get_json(force=False, silent=True)
            
            if payload is None:
                return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        except Exception as e:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        username = (payload or {}).get("username", "").strip()
        password = (payload or {}).get("password", "")
        
        if not password:
            return jsonify({"ok": False, "error": "Username and password are required"}), 400

        # Fast path for engineers - skip validation function call
        is_engineer = username.upper().startswith("EN")
        is_admin_user = username.lower() == "admin"
        
        # Only validate username format for non-engineer, non-admin users
        if not is_engineer and not is_admin_user:
            is_valid_username, username_error = validate_username(username)
            if not is_valid_username:
                return jsonify({"ok": False, "error": "Invalid username or password"}), 400

        # Normalize username for lookup
        if is_admin_user:
            search_username = "admin"
        elif is_engineer:
            search_username = username.upper()
        else:
            search_username = username
        
        # Check if account is locked before attempting login
        client_ip = request.remote_addr or "unknown"
        is_locked, lockout_until = check_account_locked(search_username, client_ip)
        if is_locked and lockout_until:
            security_logger.warning(
                f"REQ[{getattr(g, 'request_id', 'unknown')}] Account locked: {search_username} "
                f"from IP: {client_ip} until {lockout_until}"
            )
            return jsonify({
                "ok": False, 
                "error": f"Account locked due to too many failed attempts. Try again after {lockout_until.strftime('%H:%M:%S UTC')}"
            }), 429

        db: Session = get_db_session()
        login_successful = False
        try:
            # Direct database query - optimized with limit for faster lookup
            user = db.execute(select(User).where(User.username == search_username).limit(1)).scalar_one_or_none()
            if user is None:
                # Debug: Log attempted username for troubleshooting
                print(f"[LOGIN] User not found: '{search_username}' (original: '{username}')")
                # Track failed attempt (user not found)
                attempt = FailedLoginAttempt(
                    username=search_username,
                    ip_address=client_ip,
                    success=False
                )
                db.add(attempt)
                db.commit()
                return jsonify({"ok": False, "error": "Invalid username or password"}), 401
            
            # Fast password check - optimized path
            password_valid = check_password_hash(user.password_hash, password)
            if not password_valid:
                # Debug: Log password mismatch for troubleshooting
                print(f"[LOGIN] Password mismatch for user: '{search_username}'")
                # Track failed attempt (wrong password)
                attempt = FailedLoginAttempt(
                    username=search_username,
                    ip_address=client_ip,
                    success=False
                )
                db.add(attempt)
                db.commit()
                return jsonify({"ok": False, "error": "Invalid username or password"}), 401
            
            # Login successful - track successful attempt
            login_successful = True
            attempt = FailedLoginAttempt(
                username=search_username,
                ip_address=client_ip,
                success=True
            )
            db.add(attempt)
            db.commit()
            
            try:
                token = create_jwt(user)
                if isinstance(token, bytes):
                    token = token.decode('utf-8')
            except Exception as jwt_error:
                print(f"[LOGIN] Error creating JWT token: {jwt_error}")
                return jsonify({"ok": False, "error": f"Token generation failed: {str(jwt_error)}"}), 500
            
            # Log login event asynchronously (non-blocking) - don't wait for it to complete
            # This improves login response time significantly
            def log_login_event_async():
                """Log login event in background thread without blocking response"""
                try:
                    login_db: Session = get_db_session()
                    try:
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
                except Exception as e:
                    print(f"[LOGIN EVENT ERROR] Exception in async logging: {e}")
            
            # Start async logging in background thread (non-blocking)
            import threading
            threading.Thread(target=log_login_event_async, daemon=True).start()
            
            # Return response immediately without waiting for login event logging
            return jsonify({"ok": True, "token": token, "user": {"username": user.username, "role": user.role}}), 200
        except Exception as e:
            print(f"[LOGIN] Error: {e}")
            return jsonify({"ok": False, "error": "Internal server error"}), 500
        finally:
            # CRITICAL: Always close database session to prevent locking
            try:
                db.close()
            except Exception:
                pass

    @app.post("/auth/logout")
    def auth_logout():  # type: ignore[no-untyped-def]
        # Stateless JWT: client should discard the token
        return jsonify({"ok": True}), 200

    @app.get("/auth/me")
    def auth_me():  # type: ignore[no-untyped-def]
        # Optimized: Fast path for token validation
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"ok": True, "authenticated": False}), 200
        
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            user_id = payload.get("sub")
            if not user_id:
                return jsonify({"ok": True, "authenticated": False}), 200
            
            # Fast path: Return user info from token without DB query if possible
            # Only query DB if we need full user details
            return jsonify({
                "ok": True, 
                "authenticated": True, 
                "user": {
                    "id": int(user_id),
                    "username": payload.get("username", ""),
                    "role": payload.get("role", "client")
                }
            }), 200
        except Exception:
            return jsonify({"ok": True, "authenticated": False}), 200

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
        
        # Validate username
        is_valid_username, username_error = validate_username(username)
        if not is_valid_username:
            return jsonify({"ok": False, "error": username_error}), 400
        
        # Validate password strength
        is_valid_password, password_error = validate_password_strength(password)
        if not is_valid_password:
            return jsonify({"ok": False, "error": password_error}), 400

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

            # Initialize password history with first password
            password_hash = generate_password_hash(password)
            user = User(
                username=username,
                password_hash=password_hash,
                role=role,
            )
            # Initialize password history with first password
            update_password_history(user, password_hash)
            db.add(user)
            db.commit()
            return jsonify({"ok": True}), 201
        finally:
            db.close()

    @app.post("/auth/password/reset/request")
    @limiter.limit("3 per hour")  # Limit password reset requests to prevent abuse
    def password_reset_request():  # type: ignore[no-untyped-def]
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        username = (payload or {}).get("username", "").strip()
        # Validate username format
        is_valid_username, username_error = validate_username(username)
        if not is_valid_username:
            return jsonify({"ok": False, "error": username_error}), 400
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
            
            # SECURITY: In production, send token via email/SMS only
            # Only return token in development mode for testing convenience
            if is_production:
                # In production, log the token (for now) but don't return it
                # TODO: Implement email/SMS sending service
                print(f"[PASSWORD RESET] Token generated for user {username} (NOT RETURNED IN PRODUCTION)")
                print(f"[PASSWORD RESET] Token: {token} (check logs - implement email/SMS in production)")
                return jsonify({
                    "ok": True, 
                    "message": "If the username exists, a password reset token has been generated. Please check your email/SMS for the reset link."
                }), 200
            else:
                # Development mode: return token for testing convenience
                print(f"[PASSWORD RESET] Development mode: Token returned in response for user {username}")
                return jsonify({"ok": True, "resetToken": token}), 200
        finally:
            db.close()

    @app.post("/auth/password/reset/confirm")
    @limiter.limit("5 per hour")  # Limit password reset confirmations
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
            
            # Check password history (prevent reuse)
            if not check_password_history(user, new_password):
                return jsonify({"ok": False, "error": "Password was recently used. Please choose a different password."}), 400
            
            # Update password and history
            new_hash = generate_password_hash(new_password)
            update_password_history(user, new_hash)
            user.password_hash = new_hash
            
            # Consume token
            db.execute(text("DELETE FROM password_reset_tokens WHERE id = :id"), {"id": record.id})
            db.commit()
            return jsonify({"ok": True}), 200
        finally:
            db.close()

    # Project definitions API
    @app.get("/projectdefs")
    def list_projectdefs():  # type: ignore[no-untyped-def]
        """Return project definitions for both admin and engineer users.

        The list is read-only, so it's safe to expose to authenticated engineers
        (role == "client") as well as admins.
        """
        user = get_user_from_token()
        role = (user or {}).get("role")
        if role not in ("admin", "client"):
            # Still require authentication, but allow both roles
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
            "travelTimeToHomeBase": payload.get("homeTravelStart") or payload.get("travelTimeToHomeBase"),  # Accept both field names
            "travelTimeOut": payload.get("homeTravelEnd") or payload.get("travelTimeOut"),  # Accept both field names
            "onSiteTimeIn": payload.get("onSiteTimeIn"),
            "onSiteTimeOut": payload.get("onSiteTimeOut"),
        }
        for field_name, field_value in time_fields.items():
            if field_value:
                # Accept both 12-hour and 24-hour formats, convert to 12-hour for storage
                if not validate_time_format(field_value):
                    # Try to validate as 24-hour format and convert
                    if re.match(r'^([0-1][0-9]|2[0-3]):([0-5][0-9])$', field_value):
                        # Convert 24-hour to 12-hour format
                        time_fields[field_name] = convert_24_to_12(field_value)
                    else:
                        return jsonify({"ok": False, "error": f"Invalid time format for {field_name}. Expected HH:MM AM/PM or HH:MM (00:00-23:59)"}), 400
                else:
                    # Already in 12-hour format, ensure proper formatting
                    time_fields[field_name] = field_value.strip()

        # Validate text fields for XSS and length limits
        text_fields_to_validate = {
            "engineerName": (payload.get("engineerName", ""), 255),
            "projectPhase": (payload.get("projectPhase", ""), 255),
            "projectName": (payload.get("projectName", ""), 255),
            "projectCode": (payload.get("projectCode", ""), 255),
            "clientName": (payload.get("clientName", ""), 255),
            "plantLocation": (payload.get("plantLocation", ""), 255),
            "workObjective": (payload.get("workObjective", ""), 5000),
            "description": (payload.get("description", ""), 10000),
            "outcome": (payload.get("outcome", ""), 5000),
        }
        
        for field_name, (field_value, max_length) in text_fields_to_validate.items():
            if field_value:
                is_valid, error_msg = validate_text_field(field_value, field_name, max_length=max_length)
                if not is_valid:
                    return jsonify({"ok": False, "error": error_msg}), 400
        
        # If user is authenticated, use their username as engineer_name for consistent filtering
        engineer_name = payload.get("engineerName", "")
        if user and user.get("username"):
            # Store as "username (original name)" so we can filter by username but keep the original info
            original_name = payload.get("engineerName", "")
            engineer_name = f"{user.get('username')} - {original_name}" if original_name else user.get('username')

        engineer_signature_value = normalize_signature_value(payload.get("engineerSignature"))
        customer_signature_value = normalize_signature_value(payload.get("customerSignature"))

        max_retries = 3  # Reduced from 5 for faster failure detection
        retry_delay = 0.1  # Reduced from 0.3 seconds for faster retries
        import time
        
        for attempt in range(max_retries):
            session = None
            try:
                session = get_db_session()
                # Create a new Report object for each attempt
                new_report = Report(
                    report_date=payload.get("reportDate", ""),
                    engineer_name=engineer_name or "",
                    project_phase=payload.get("projectPhase", ""),
                    project_name=payload.get("projectName", ""),
                    project_code=payload.get("projectCode", ""),
                    client_name=payload.get("clientName", ""),
                    plant_location=payload.get("plantLocation", ""),
                    travel_time_to_site=time_fields.get("travelTimeToSite", ""),
                    travel_time_from_site=time_fields.get("travelTimeFromSite", ""),
                    travel_time_to_home_base=time_fields.get("travelTimeToHomeBase", ""),
                    travel_time_out=time_fields.get("travelTimeOut", ""),
                    onsite_time_in=time_fields.get("onSiteTimeIn", ""),
                    onsite_time_out=time_fields.get("onSiteTimeOut", ""),
                    work_objective=payload.get("workObjective", ""),
                    description=payload.get("description", ""),
                    outcome=payload.get("outcome", ""),
                    engineer_signature=engineer_signature_value,
                    customer_signature=customer_signature_value,
                )
                
                session.add(new_report)
                session.commit()
                # Get report_id directly without refresh for faster response
                report_id = new_report.id
                # Close session before returning for faster response
                session.close()
                return jsonify({"ok": True, "status": "ok", "id": report_id}), 200
            except Exception as exc:  # noqa: BLE001
                if session:
                    try:
                        session.rollback()
                    except Exception:
                        pass
                    try:
                        session.close()
                    except Exception:
                        pass
                
                error_msg = str(exc)
                error_lower = error_msg.lower()
                
                # Check if it's a database locked error
                if "database is locked" in error_lower or ("locked" in error_lower and "sqlite3" in error_lower):
                    if attempt < max_retries - 1:
                        # Wait and retry with exponential backoff (reduced initial delay)
                        wait_time = retry_delay * (2 ** attempt)
                        time.sleep(wait_time)
                        continue
                    else:
                        # Final attempt failed
                        detailed_error = "Database is locked. Please ensure only one server instance is running. If the problem persists, restart the server."
                        return jsonify({"ok": False, "error": detailed_error, "detail": error_msg}), 500
                else:
                    # Other database errors - don't retry, return immediately
                    if "no such column" in error_lower or "does not exist" in error_lower:
                        detailed_error = f"Database schema error: Missing column. Please restart the server to apply migrations."
                    elif "no such table" in error_lower:
                        detailed_error = f"Database error: Table not found. Please restart the server to create tables."
                    elif "connection" in error_lower or "operational" in error_lower:
                        detailed_error = f"Database connection error. Please check if the database is accessible."
                    else:
                        detailed_error = f"Database error: {error_msg}"
                    return jsonify({"ok": False, "error": detailed_error}), 500
        
        # Should never reach here, but just in case
        return jsonify({"ok": False, "error": "Failed to submit report after retries"}), 500

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

            def to_dict(r: "Report") -> dict:
                return {
                    "id": r.id,
                    "reportDate": r.report_date,
                    "engineerName": r.engineer_name,
                    "projectPhase": r.project_phase,
                    "projectName": r.project_name,
                    "projectCode": r.project_code,
                    "clientName": r.client_name,
                    "plantLocation": r.plant_location,
                    "travelTimeToSite": convert_24_to_12(r.travel_time_to_site) if r.travel_time_to_site else None,
                    "travelTimeFromSite": convert_24_to_12(r.travel_time_from_site) if r.travel_time_from_site else None,
                    "travelTimeToHomeBase": convert_24_to_12(r.travel_time_to_home_base) if r.travel_time_to_home_base else None,
                    "travelTimeOut": convert_24_to_12(r.travel_time_out) if r.travel_time_out else None,
                    "onSiteTimeIn": convert_24_to_12(r.onsite_time_in) if r.onsite_time_in else None,
                    "onSiteTimeOut": convert_24_to_12(r.onsite_time_out) if r.onsite_time_out else None,
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
                    "projectPhase": r.project_phase,
                    "projectName": r.project_name,
                    "projectCode": r.project_code,
                    "clientName": r.client_name,
                    "plantLocation": r.plant_location,
                    "travelTimeToSite": convert_24_to_12(r.travel_time_to_site) if r.travel_time_to_site else None,
                    "travelTimeFromSite": convert_24_to_12(r.travel_time_from_site) if r.travel_time_from_site else None,
                    "travelTimeToHomeBase": convert_24_to_12(r.travel_time_to_home_base) if r.travel_time_to_home_base else None,
                    "travelTimeOut": convert_24_to_12(r.travel_time_out) if r.travel_time_out else None,
                    "onSiteTimeIn": convert_24_to_12(r.onsite_time_in) if r.onsite_time_in else None,
                    "onSiteTimeOut": convert_24_to_12(r.onsite_time_out) if r.onsite_time_out else None,
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
                
                # Only fetch engineer (client) logins, exclude admin logins at the database query level
                if since:
                    try:
                        # Parse ISO timestamp and ensure it's timezone-aware (UTC)
                        since_time = datetime.fromisoformat(since.replace('Z', '+00:00'))
                        # If the parsed time is naive, assume UTC
                        if since_time.tzinfo is None:
                            since_time = since_time.replace(tzinfo=timezone.utc)
                            
                        # Query only client role logins (engineers) since the specified time
                        login_stmt = select(LoginEvent).where(
                            LoginEvent.role == "client",
                            LoginEvent.login_time >= since_time
                        ).order_by(LoginEvent.login_time.desc()).limit(100)
                        print(f"[NOTIFICATIONS API] Fetching engineer login events since: {since_time.isoformat()}")
                    except Exception as e:
                        print(f"[NOTIFICATIONS API] Error parsing 'since' parameter: {e}, fetching all recent engineer events")
                        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
                        login_stmt = select(LoginEvent).where(
                            LoginEvent.role == "client",
                            LoginEvent.login_time > seven_days_ago
                        ).order_by(LoginEvent.login_time.desc()).limit(100)
                else:
                    # On initial load (loadAll=true), fetch recent engineer login events only (last 30 days, max 500)
                    # This ensures admin sees recent engineer logins without overwhelming the system
                    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
                    login_stmt = select(LoginEvent).where(
                        LoginEvent.role == "client",
                        LoginEvent.login_time >= thirty_days_ago
                    ).order_by(LoginEvent.login_time.desc()).limit(500)
                    print(f"[NOTIFICATIONS API] Fetching recent engineer login events only (last 30 days, max 500)")
                
                login_events = db.execute(login_stmt).scalars().all()
                print(f"[NOTIFICATIONS API] Found {len(login_events)} engineer login events in database (admin logins excluded)")
                if len(login_events) > 0:
                    print(f"[NOTIFICATIONS API] Most recent engineer login: {login_events[0].username} at {login_events[0].login_time.isoformat()}")
                    if len(login_events) > 1:
                        print(f"[NOTIFICATIONS API] Oldest engineer login in results: {login_events[-1].username} at {login_events[-1].login_time.isoformat()}")
                else:
                    print(f"[NOTIFICATIONS API] No engineer login events found in database")
                
                # All events returned are engineer logins (client role), no need to filter
                for event in login_events:
                    print(f"[NOTIFICATIONS API] Adding engineer login notification: {event.username}")
                    
                    role_label = "Engineer"
                    # Ensure time is in UTC format with Z suffix
                    time_str = event.login_time.isoformat()
                    if '+00:00' in time_str:
                        time_str = time_str.replace('+00:00', 'Z')
                    elif not time_str.endswith('Z') and not ('+' in time_str or '-' in time_str[-6:]):
                        time_str = time_str + 'Z'
                    notifications.append({
                        "id": f"login-{event.id}",
                        "type": "login",
                        "message": f"{event.username} ({role_label}) logged in",
                        "time": time_str,
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
                    
                    # Ensure time is in UTC format with Z suffix
                    time_str = report.created_at.isoformat()
                    if '+00:00' in time_str:
                        time_str = time_str.replace('+00:00', 'Z')
                    elif not time_str.endswith('Z') and not ('+' in time_str or '-' in time_str[-6:]):
                        time_str = time_str + 'Z'
                    print(f"[NOTIFICATIONS API] Adding report notification: Report ID {report.id} by {engineer_name}")
                    notifications.append({
                        "id": f"report-{report.id}",
                        "type": "report",
                        "message": f"Report submitted by {engineer_name}{project_info}",
                        "time": time_str,
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
            
            # Summary logging
            login_count = sum(1 for n in notifications if n.get("type") == "login")
            report_count = sum(1 for n in notifications if n.get("type") == "report")
            print(f"[NOTIFICATIONS API] Total notifications prepared: {len(notifications)}")
            print(f"[NOTIFICATIONS API]   - Login notifications: {login_count}")
            print(f"[NOTIFICATIONS API]   - Report notifications: {report_count}")
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
    
    @app.get("/admin/security/events")
    def get_security_events():  # type: ignore[no-untyped-def]
        """Get security events (admin only) - failed login attempts, blocked IPs, etc."""
        user = get_user_from_token()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        
        db = get_db_session()
        try:
            # Get recent failed login attempts (last 24 hours)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            failed_attempts = db.execute(
                select(FailedLoginAttempt)
                .where(FailedLoginAttempt.attempt_time >= cutoff)
                .where(FailedLoginAttempt.success == False)
                .order_by(FailedLoginAttempt.attempt_time.desc())
                .limit(100)
            ).scalars().all()
            
            # Get IP statistics
            ip_stats = db.execute(
                text("""
                    SELECT ip_address, COUNT(*) as attempt_count, 
                           MAX(attempt_time) as last_attempt
                    FROM failed_login_attempts
                    WHERE attempt_time >= :cutoff AND success = false
                    GROUP BY ip_address
                    ORDER BY attempt_count DESC
                    LIMIT 20
                """),
                {"cutoff": cutoff}
            ).fetchall()
            
            # Get account lockout status
            max_attempts = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
            lockout_minutes = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
            lockout_cutoff = datetime.now(timezone.utc) - timedelta(minutes=lockout_minutes)
            
            locked_accounts = db.execute(
                text("""
                    SELECT username, COUNT(*) as failed_count, 
                           MIN(attempt_time) as first_failed,
                           MAX(attempt_time) as last_failed
                    FROM failed_login_attempts
                    WHERE attempt_time >= :cutoff AND success = false
                    GROUP BY username
                    HAVING COUNT(*) >= :max_attempts
                    ORDER BY last_failed DESC
                """),
                {"cutoff": lockout_cutoff, "max_attempts": max_attempts}
            ).fetchall()
            
            return jsonify({
                "ok": True,
                "failed_attempts": [
                    {
                        "username": attempt.username,
                        "ip_address": attempt.ip_address,
                        "attempt_time": attempt.attempt_time.isoformat(),
                    }
                    for attempt in failed_attempts
                ],
                "ip_statistics": [
                    {
                        "ip_address": row[0],
                        "attempt_count": row[1],
                        "last_attempt": row[2].isoformat() if isinstance(row[2], datetime) else str(row[2]),
                    }
                    for row in ip_stats
                ],
                "locked_accounts": [
                    {
                        "username": row[0],
                        "failed_count": row[1],
                        "first_failed": row[2].isoformat() if isinstance(row[2], datetime) else str(row[2]),
                        "last_failed": row[3].isoformat() if isinstance(row[3], datetime) else str(row[3]),
                    }
                    for row in locked_accounts
                ],
                "summary": {
                    "total_failed_attempts_24h": len(failed_attempts),
                    "unique_ips": len(ip_stats),
                    "locked_accounts": len(locked_accounts),
                }
            }), 200
        finally:
            db.close()

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
    # Performance optimizations for faster response times
    # threaded=True: Enable multi-threading for concurrent requests (ALWAYS enable for better performance)
    # use_reloader: Only in debug mode (faster startup when disabled)
    threaded = True  # ALWAYS enable threading for concurrent request handling - much faster!
    use_reloader = debug  # Only reload in debug mode
    
    print("[PERFORMANCE] Threading enabled for concurrent request handling")
    if use_reloader:
        print("[PERFORMANCE] Auto-reloader enabled (debug mode)")
    else:
        print("[PERFORMANCE] Auto-reloader disabled for better performance")
    
    try:
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=threaded,
            use_reloader=use_reloader
        )
    except OSError as e:
        if "Address already in use" in str(e) or "address is already in use" in str(e).lower():
            print(f"\n{'='*60}")
            print(f"ERROR: Port {port} is already in use!")
            print(f"{'='*60}")
            print(f"\nAnother process is using port {port}.")
            print("Please either:")
            print(f"  1. Stop the other process using port {port}")
            print(f"  2. Set FLASK_PORT environment variable to use a different port")
            print(f"  3. Kill the process: netstat -ano | findstr :{port}")
            print(f"\n{'='*60}\n")
        else:
            print(f"\n{'='*60}")
            print(f"ERROR: Failed to start server: {e}")
            print(f"{'='*60}\n")
        raise
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"ERROR: Unexpected error starting server: {e}")
        print(f"{'='*60}\n")
        import traceback
        traceback.print_exc()
        raise


