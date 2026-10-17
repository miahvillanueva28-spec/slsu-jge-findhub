
database_url = os.environ.get("DATABASE_URL", "").strip()

# Render PostgreSQL URL compatibility
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql+psycopg://", 1
    )
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

# Local SQLite fallback; on Render Free, local files may be temporary.
if not database_url:
    database_url = "sqlite:///" + str(
        (DATA_DIR / "findhub.db").resolve()
    )

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "true").lower() == "true"
        and os.environ.get("RENDER") is not None
    ),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)

# Optional Cloudinary photo storage.
cloudinary = None
CLOUDINARY_ENABLED = False

try:
    import cloudinary as _cloudinary
    import cloudinary.uploader as _cloudinary_uploader

    cloudinary = _cloudinary

    cloudinary_url = os.environ.get("CLOUDINARY_URL", "").strip()
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME", "").strip()
    api_key = os.environ.get("CLOUDINARY_API_KEY", "").strip()
    api_secret = os.environ.get("CLOUDINARY_API_SECRET", "").strip()

    if cloudinary_url:
        cloudinary.config(
            cloudinary_url=cloudinary_url,
            secure=True,
        )
        CLOUDINARY_ENABLED = True
    elif cloud_name and api_key and api_secret:
        cloudinary.config(
            cloud_name=cloud_name,
            api_key=api_key,
            api_secret=api_secret,
            secure=True,
        )
        CLOUDINARY_ENABLED = True

except ImportError:
    app.logger.warning(
        "Cloudinary package is not installed; using local photo storage."
    )
