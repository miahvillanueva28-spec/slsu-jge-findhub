
import os
import csv
import io
import hmac
import secrets
from pathlib import Path
from datetime import date, datetime
from functools import wraps

import cloudinary
import cloudinary.uploader

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    make_response,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.utils import secure_filename


# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(
    os.environ.get("DATA_DIR", str(BASE_DIR / "data"))
).resolve()

UPLOAD_FOLDER = DATA_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "true").lower() == "true"
)

# --------------------------------------------------
# DATABASE
# --------------------------------------------------

database_url = os.environ.get("DATABASE_URL", "").strip()

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

if database_url.startswith("postgresql+psycopg://"):
    database_url = database_url.replace(
        "postgresql+psycopg://", "postgresql://", 1
    )

if not database_url:
    # Local development only.
    # Render should have DATABASE_URL set to PostgreSQL.
    database_url = f"sqlite:///{DATA_DIR / 'findhub.db'}"

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
}

db = SQLAlchemy(app)


# --------------------------------------------------
# CLOUDINARY PHOTO STORAGE
# --------------------------------------------------

CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL", "").strip()
USE_CLOUDINARY = bool(CLOUDINARY_URL)

if USE_CLOUDINARY:
    cloudinary.config(cloudinary_url=CLOUDINARY_URL)


# --------------------------------------------------
# WEBSITE BRANDING
# --------------------------------------------------

CAMPUS_LOGO = (
    "https://www.slsu.edu.ph/wp-content/uploads/2023/05/"
    "Campuses/Campus-Logo/SLSU-JGE-Logo.png"
)

CAMPUS_PHOTO = (
    "https://www.slsu.edu.ph/wp-content/uploads/2023/05/"
    "Campuses/SLSU%20JGE%20Tagkawayan/JGE%20bldg.jpg"
)


@app.context_processor
def inject_global_template_values():
    return {
        "today": date.today(),
        "campus_logo": CAMPUS_LOGO,
        "campus_photo": CAMPUS_PHOTO,
        "admin_logged_in": bool(session.get("admin_logged_in")),
    }


# --------------------------------------------------
# DATABASE MODELS
# --------------------------------------------------

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    report_type = db.Column(db.String(20), nullable=False)
    item_name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    incident_date = db.Column(db.Date, nullable=False)

    contact_name = db.Column(db.String(120), nullable=False)
    contact = db.Column(db.String(150), nullable=False)
    contact_public = db.Column(db.Boolean, default=False, nullable=False)

    # Stores a Cloudinary URL or a local uploaded filename.
    photo = db.Column(db.String(1000), nullable=True)

    status = db.Column(db.String(30), default="Open", nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    claims = db.relationship(
        "Claim",
        backref="report",
        cascade="all, delete-orphan",
        lazy=True,
    )


class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    report_id = db.Column(
        db.Integer,
        db.ForeignKey("report.id"),
        nullable=False,
    )

    claimant_name = db.Column(db.String(120), nullable=False)
    claimant_contact = db.Column(db.String(150), nullable=False)
    proof = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(30), default="Pending", nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


# Create tables that do not yet exist.
# This does NOT migrate or alter existing database tables.
with app.app_context():
    db.create_all()


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

REPORT_STATUSES = {
    "Open",
    "Pending Claim",
    "Returned",
    "Archived",
}

CLAIM_STATUSES = {
    "Pending",
    "Approved",
    "Rejected",
}


def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in as an administrator first.", "warning")
            return redirect(url_for("admin_login"))
        return view_function(*args, **kwargs)

    return wrapped_view


def allowed_file(filename):
    return (
        bool(filename)
        and "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def photo_src(photo):
    """Return the URL used to display an uploaded photo."""
    if not photo:
        return None

    if photo.startswith(("https://", "http://")):
        return photo

    return url_for("uploaded_photo", filename=photo)


@app.context_processor
def inject_photo_helper():
    return {"photo_src": photo_src}


def save_photo(file_storage):
    """Save a photo to Cloudinary, or local disk for development."""
    if not file_storage or not file_storage.filename:
        return None

    original_name = secure_filename(file_storage.filename)

    if not allowed_file(original_name):
        raise ValueError("Unsupported photo format.")

    if USE_CLOUDINARY:
        result = cloudinary.uploader.upload(
            file_storage,
            folder="slsu-jge-findhub",
            resource_type="image",
        )
        return result["secure_url"]

    # Local disk is suitable for development, not persistent Render storage.
    filename = f"{secrets.token_hex(12)}_{original_name}"
    file_storage.save(UPLOAD_FOLDER / filename)
    return filename


def delete_photo(photo):
    """Delete local files only. Cloudinary cleanup can be done separately."""
    if not photo or photo.startswith(("https://", "http://")):
        return

    filename = Path(photo).name
    path = UPLOAD_FOLDER / filename

    try:
        if path.is_file():
            path.unlink()
    except OSError:
        app.logger.exception("Unable to delete local photo")


def parse_incident_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def get_report_form_value(name, default=""):
    return (request.form.get(name, default) or "").strip()


# --------------------------------------------------
# HOME AND SEARCH
# --------------------------------------------------

@app.route("/")
def home():
    report_type = request.args.get("type", "").strip()
    category = request.args.get("category", "").strip()
    status = request.args.get("status", "").strip()
    query = request.args.get("q", "").strip()
    sort = request.args.get("sort", "newest").strip()

    reports_query = Report.query

    if report_type in {"Lost", "Found"}:
        reports_query = reports_query.filter(
            Report.report_type == report_type
        )

    if category:
        reports_query = reports_query.filter(
            Report.category == category
        )

    if status in REPORT_STATUSES:
        reports_query = reports_query.filter(Report.status == status)

    if query:
        search_term = f"%{query}%"
        reports_query = reports_query.filter(
            or_(
                Report.item_name.ilike(search_term),
                Report.category.ilike(search_term),
                Report.location.ilike(search_term),
                Report.description.ilike(search_term),
            )
        )

    if sort == "oldest":
        reports_query = reports_query.order_by(Report.created_at.asc())
    elif sort == "name":
        reports_query = reports_query.order_by(Report.item_name.asc())
    else:
        reports_query = reports_query.order_by(Report.created_at.desc())

    reports = reports_query.all()

    stats = {
        "total": Report.query.count(),
        "lost": Report.query.filter_by(report_type="Lost").count(),
        "found": Report.query.filter_by(report_type="Found").count(),
        "open": Report.query.filter_by(status="Open").count(),
    }

    return render_template(
        "home.html",
        reports=reports,
        stats=stats,
        query=query,
        selected_type=report_type,
        selected_category=category,
        selected_status=status,
        selected_sort=sort,
    )


# --------------------------------------------------
# CREATE A REPORT
# --------------------------------------------------

@app.route("/report/new", methods=["GET", "POST"])
def new_report():
    if request.method == "POST":
        report_type = get_report_form_value("report_type")
        item_name = get_report_form_value("item_name")
        category = get_report_form_value("category")
        description = get_report_form_value("description")
        location = get_report_form_value("location")
        incident_date = parse_incident_date(
            get_report_form_value("incident_date")
        )
        contact_name = get_report_form_value("contact_name")
        contact = get_report_form_value("contact")
        contact_public = request.form.get("contact_public") in {
            "1", "true", "on", "yes"
        }

        if report_type not in {"Lost", "Found"}:
            flash("Please select Lost or Found.", "danger")
            return redirect(url_for("new_report"))

        if not all([
            item_name,
            category,
            description,
            location,
            incident_date,
            contact_name,
            contact,
        ]):
            flash("Please complete all required fields.", "danger")
            return redirect(url_for("new_report"))

        photo_file = request.files.get("photo")

        try:
            saved_photo = save_photo(photo_file)
        except ValueError:
            flash("Use a PNG, JPG, JPEG, GIF, or WEBP image.", "danger")
            return redirect(url_for("new_report"))
        except Exception:
            app.logger.exception("Photo upload failed")
            flash(
                "Photo upload failed. Check the photo storage configuration.",
                "danger",
            )
            return redirect(url_for("new_report"))

        report = Report(
            report_type=report_type,
            item_name=item_name,
            category=category,
            description=description,
            location=location,
            incident_date=incident_date,
            contact_name=contact_name,
            contact=contact,
            contact_public=contact_public,
            photo=saved_photo,
            status="Open",
        )

        try:
            db.session.add(report)
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Unable to save report")
            flash("Unable to save your report. Please try again.", "danger")
            return redirect(url_for("new_report"))

        flash("Your report was submitted successfully.", "success")
        return redirect(url_for("report_detail", report_id=report.id))

    return render_template("report_form.html")


# --------------------------------------------------
# REPORT DETAILS
# --------------------------------------------------

@app.route("/report/<int:report_id>")
def report_detail(report_id):
    report = db.get_or_404(Report, report_id)
    return render_template("report_detail.html", report=report)


# --------------------------------------------------
# CLAIM SUBMISSION
# --------------------------------------------------

@app.route("/report/<int:report_id>/claim", methods=["POST"])
def submit_claim(report_id):
    report = db.get_or_404(Report, report_id)

    if report.status in {"Returned", "Archived"}:
        flash("This report is no longer accepting claim requests.", "warning")
        return redirect(url_for("report_detail", report_id=report.id))

    claimant_name = get_report_form_value("claimant_name")
    claimant_contact = get_report_form_value("claimant_contact")
    proof = get_report_form_value("proof")

    if not all([claimant_name, claimant_contact, proof]):
        flash(
            "Complete your name, contact details, and ownership proof.",
            "danger",
        )
        return redirect(url_for("report_detail", report_id=report.id))

    claim = Claim(
        report_id=report.id,
        claimant_name=claimant_name,
        claimant_contact=claimant_contact,
        proof=proof,
        status="Pending",
    )

    try:
        db.session.add(claim)
        report.status = "Pending Claim"
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Unable to save claim")
        flash("Unable to submit your claim. Please try again.", "danger")
        return redirect(url_for("report_detail", report_id=report.id))

    flash("Claim request submitted for administrator review.", "success")
    return redirect(url_for("report_detail", report_id=report.id))


# --------------------------------------------------
# SERVE LOCAL PHOTOS
# --------------------------------------------------

@app.route("/uploads/<path:filename>")
def uploaded_photo(filename):
    # Cloudinary URLs are returned directly by photo_src().
    return send_from_directory(UPLOAD_FOLDER, filename)


# --------------------------------------------------
# ADMIN LOGIN
# --------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        expected_username = os.environ.get("ADMIN_USERNAME", "")
        expected_password = os.environ.get("ADMIN_PASSWORD", "")

        if not expected_username or not expected_password:
            flash(
                "Admin credentials are not configured on the server.",
                "danger",
            )
            return render_template("admin_login.html")

        valid_username = hmac.compare_digest(
            username, expected_username
        )
        valid_password = hmac.compare_digest(
            password, expected_password
        )

        if valid_username and valid_password:
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"] = expected_username
            flash("Welcome to the admin dashboard.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("admin_login.html")


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    reports = Report.query.order_by(Report.created_at.desc()).all()

    latest_claims = Claim.query.order_by(
        Claim.created_at.desc()
    ).limit(6).all()

    stats = {
        "total": Report.query.count(),
        "lost": Report.query.filter_by(report_type="Lost").count(),
        "found": Report.query.filter_by(report_type="Found").count(),
        "open": Report.query.filter_by(status="Open").count(),
        "pending_claims": Claim.query.filter_by(status="Pending").count(),
        "returned": Report.query.filter_by(status="Returned").count(),
    }

    return render_template(
        "admin_dashboard.html",
        reports=reports,
        claims=latest_claims,
        latest_claims=latest_claims,
        stats=stats,
    )


# --------------------------------------------------
# ADMIN: UPDATE REPORT STATUS
# --------------------------------------------------

@app.route(
    "/admin/report/<int:report_id>/status",
    methods=["POST"],
)
@admin_required
def admin_update_report_status(report_id):
    report = db.get_or_404(Report, report_id)
    new_status = get_report_form_value("status")

    if new_status not in REPORT_STATUSES:
        flash("Invalid report status.", "danger")
        return redirect(url_for("admin_dashboard"))

    report.status = new_status

    try:
        db.session.commit()
        flash("Report status updated.", "success")
    except Exception:
        db.session.rollback()
        app.logger.exception("Report status update failed")
        flash("Unable to update report status.", "danger")

    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# ADMIN: DELETE REPORT
# --------------------------------------------------

@app.route(
    "/admin/report/<int:report_id>/delete",
    methods=["POST"],
)
@admin_required
def admin_delete_report(report_id):
    report = db.get_or_404(Report, report_id)
    photo = report.photo

    try:
        db.session.delete(report)
        db.session.commit()
        delete_photo(photo)
        flash("Report deleted.", "success")
    except Exception:
        db.session.rollback()
        app.logger.exception("Report deletion failed")
        flash("Unable to delete report.", "danger")

    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# ADMIN: VIEW CLAIMS
# --------------------------------------------------

@app.route("/admin/claims")
@admin_required
def admin_claims():
    claims = Claim.query.order_by(Claim.created_at.desc()).all()
    return render_template("admin_claims.html", claims=claims)


# --------------------------------------------------
# ADMIN: UPDATE CLAIM STATUS
# --------------------------------------------------

@app.route(
    "/admin/claim/<int:claim_id>/status",
    methods=["POST"],
)
@admin_required
def admin_update_claim_status(claim_id):
    claim = db.get_or_404(Claim, claim_id)
    new_status = get_report_form_value("status")

    if new_status not in CLAIM_STATUSES:
        flash("Invalid claim status.", "danger")
        return redirect(url_for("admin_claims"))

    claim.status = new_status

    if new_status == "Approved":
        claim.report.status = "Returned"
    elif new_status == "Rejected":
        other_pending_claims = Claim.query.filter(
            Claim.report_id == claim.report_id,
            Claim.status == "Pending",
            Claim.id != claim.id,
        ).count()

        if other_pending_claims == 0 and claim.report.status == "Pending Claim":
            claim.report.status = "Open"

    try:
        db.session.commit()
        flash("Claim status updated.", "success")
    except Exception:
        db.session.rollback()
        app.logger.exception("Claim status update failed")
        flash("Unable to update claim status.", "danger")

    return redirect(url_for("admin_claims"))


# --------------------------------------------------
# ADMIN: CSV EXPORT
# --------------------------------------------------

@app.route("/admin/export.csv")
@admin_required
def export_reports():
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Type",
        "Item",
        "Category",
        "Description",
        "Location",
        "Incident Date",
        "Contact Name",
        "Contact",
        "Status",
        "Created At",
    ])

    reports = Report.query.order_by(Report.created_at.desc()).all()

    for report in reports:
        writer.writerow([
            report.id,
            report.report_type,
            report.item_name,
            report.category,
            report.description,
            report.location,
            report.incident_date.isoformat() if report.incident_date else "",
            report.contact_name,
            report.contact,
            report.status,
            report.created_at.isoformat() if report.created_at else "",
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=findhub_reports.csv"
    )
    return response


# --------------------------------------------------
# ADMIN LOGOUT
# --------------------------------------------------

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# --------------------------------------------------
# ERROR HANDLERS AND SECURITY HEADERS
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(_error):
    flash("The uploaded file is too large. Maximum size is 5 MB.", "danger")
    return redirect(request.referrer or url_for("new_report"))


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


# --------------------------------------------------
# LOCAL DEVELOPMENT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
