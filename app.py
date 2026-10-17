
import csv
import io
import os
import secrets
from datetime import date, datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, make_response, redirect, render_template,
    request, send_from_directory, session, url_for
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
UPLOAD_DIR = DATA_DIR / "uploads"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if not database_url:
    database_url = "sqlite:///" + str((DATA_DIR / "findhub.db").resolve())

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)

# Optional permanent photo storage through Cloudinary.
try:
    import cloudinary
    import cloudinary.uploader

    CLOUDINARY_ENABLED = bool(os.environ.get("CLOUDINARY_URL"))

    if CLOUDINARY_ENABLED:
        cloudinary.config(secure=True)

except ImportError:
    CLOUDINARY_ENABLED = False


db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
REPORT_TYPES = {"Lost", "Found"}
REPORT_STATUSES = {"Open", "Pending Claim", "Returned", "Archived"}

CATEGORIES = [
    "ID / School Card",
    "Wallet / Money",
    "Phone / Gadget",
    "Keys",
    "Bag",
    "Clothing",
    "Books / Notes",
    "Other",
]

CAMPUS_LOGO = (
    "https://www.slsu.edu.ph/wp-content/uploads/2023/05/"
    "Campuses/Campus-Logo/SLSU-JGE-Logo.png"
)

CAMPUS_PHOTO = (
    "https://www.slsu.edu.ph/wp-content/uploads/2023/05/"
    "Campuses/SLSU%20JGE%20Tagkawayan/JGE%20bldg.jpg"
)


# =========================================================
# DATABASE MODELS
# =========================================================

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10), nullable=False)
    item_name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(60), nullable=False, default="Other")
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(180), nullable=False)
    incident_date = db.Column(db.String(10), nullable=False)
    contact_name = db.Column(db.String(120))
    contact = db.Column(db.String(180))
    contact_public = db.Column(db.Boolean, default=False, nullable=False)
    photo = db.Column(db.String(255))
    status = db.Column(db.String(30), default="Open", nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False
    )


class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer, db.ForeignKey("report.id"), nullable=False
    )
    claimant_name = db.Column(db.String(120), nullable=False)
    student_or_staff_id = db.Column(db.String(80))
    contact = db.Column(db.String(180), nullable=False)
    proof = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pending", nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False
    )

    report = db.relationship(
        "Report",
        backref=db.backref(
            "claims",
            lazy=True,
            cascade="all, delete-orphan"
        )
    )


with app.app_context():
    db.create_all()


# =========================================================
# HELPERS
# =========================================================

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in to access the admin area.", "warning")
            return redirect(url_for("admin_login"))

        return view(*args, **kwargs)

    return wrapped


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.context_processor
def inject_globals():
    return {
        "campus_logo": CAMPUS_LOGO,
        "campus_photo": CAMPUS_PHOTO,
        "today": date.today(),
        "admin_logged_in": bool(session.get("is_admin")),
    }


@app.context_processor
def inject_photo_helpers():
    def photo_src(photo):
        if not photo:
            return ""

        if photo.startswith(("https://", "http://")):
            return photo

        return url_for("uploaded_photo", filename=photo)

    return {"photo_src": photo_src}


# =========================================================
# HOME PAGE, SEARCH, FILTERS AND SORTING
# =========================================================

@app.route("/")
def home():
    query = Report.query.filter(Report.status != "Archived")

    kind = request.args.get("type", "").strip()
    category = request.args.get("category", "").strip()
    status = request.args.get("status", "").strip()
    search = request.args.get("q", "").strip()
    sort = request.args.get("sort", "newest").strip()

    if kind in REPORT_TYPES:
        query = query.filter_by(report_type=kind)

    if category in CATEGORIES:
        query = query.filter_by(category=category)

    if status in {"Open", "Pending Claim", "Returned"}:
        query = query.filter_by(status=status)

    if search:
        term = f"%{search}%"
        query = query.filter(
            db.or_(
                Report.item_name.ilike(term),
                Report.description.ilike(term),
                Report.location.ilike(term),
                Report.category.ilike(term),
            )
        )

    if sort == "oldest":
        reports = query.order_by(Report.created_at.asc()).all()
    elif sort == "name":
        reports = query.order_by(Report.item_name.asc()).all()
    else:
        sort = "newest"
        reports = query.order_by(Report.created_at.desc()).all()

    total_open = Report.query.filter(
        Report.status.notin_(["Returned", "Archived"])
    ).count()

    total_found = Report.query.filter(
        Report.report_type == "Found",
        Report.status != "Archived"
    ).count()

    total_lost = Report.query.filter(
        Report.report_type == "Lost",
        Report.status != "Archived"
    ).count()

    return render_template(
        "home.html",
        reports=reports,
        kind=kind,
        category=category,
        status=status,
        q=search,
        sort=sort,
        total_open=total_open,
        total_found=total_found,
        total_lost=total_lost,
        categories=CATEGORIES,
    )


# =========================================================
# CREATE A LOST OR FOUND REPORT
# =========================================================

@app.route("/report/new", methods=["GET", "POST"])
def new_report():
    if request.method == "POST":
        kind = request.form.get("report_type", "").strip()
        name = request.form.get("item_name", "").strip()
        category = request.form.get("category", "Other").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        incident_date = request.form.get("incident_date", "").strip()
        contact_name = request.form.get("contact_name", "").strip()
        contact = request.form.get("contact", "").strip()
        contact_public = request.form.get("contact_public") == "yes"

        if not all([
            kind, name, description, location, incident_date, contact
        ]):
            flash(
                "Please complete all required fields, including a private contact method.",
                "warning"
            )
            return redirect(url_for("new_report"))

        if kind not in REPORT_TYPES or category not in CATEGORIES:
            abort(400)

        try:
            parsed = date.fromisoformat(incident_date)

            if parsed > date.today():
                raise ValueError

        except ValueError:
            flash(
                "Please choose a valid date that is not in the future.",
                "warning"
            )
            return redirect(url_for("new_report"))

        photo_name = None
        upload = request.files.get("photo")

        if upload and upload.filename:
            if not allowed_file(upload.filename):
                flash(
                    "Photo must be JPG, JPEG, PNG, or WEBP.",
                    "warning"
                )
                return redirect(url_for("new_report"))

            safe = secure_filename(upload.filename)

            if not safe or "." not in safe:
                flash("Please choose a valid image file.", "warning")
                return redirect(url_for("new_report"))

            extension = safe.rsplit(".", 1)[1].lower()
            photo_name = f"{secrets.token_hex(16)}.{extension}"

            try:
                if CLOUDINARY_ENABLED:
                    result = cloudinary.uploader.upload(
                        upload.stream,
                        folder="slsu_jge_findhub",
                        resource_type="image",
                        use_filename=False,
                        unique_filename=True,
                    )
                    photo_name = result["secure_url"]
                else:
                    upload.save(UPLOAD_DIR / photo_name)

            except Exception:
                app.logger.exception("Could not save uploaded image")
                flash(
                    "The photo could not be saved. Check image-storage configuration and try again.",
                    "danger"
                )
                return redirect(url_for("new_report"))

        report = Report(
            report_type=kind,
            item_name=name[:120],
            category=category,
            description=description[:3000],
            location=location[:180],
            incident_date=incident_date,
            contact_name=contact_name[:120] or None,
            contact=contact[:180],
            contact_public=contact_public,
            photo=photo_name,
        )

        db.session.add(report)

        try:
            db.session.commit()

        except Exception:
            db.session.rollback()

            if photo_name and not photo_name.startswith(
                ("https://", "http://")
            ):
                try:
                    (UPLOAD_DIR / photo_name).unlink(missing_ok=True)
                except OSError:
                    pass

            app.logger.exception("Failed to save report")
            flash(
                "Sorry, your report could not be saved. Please try again.",
                "danger"
            )
            return redirect(url_for("new_report"))

        flash(
            "Your report was submitted successfully and is now visible on FindHub!",
            "success"
        )

        return redirect(
            url_for("report_detail", report_id=report.id)
        )

    return render_template("report_form.html", categories=CATEGORIES)


# =========================================================
# REPORT DETAILS
# =========================================================

@app.route("/report/<int:report_id>")
def report_detail(report_id):
    report = db.get_or_404(Report, report_id)

    if report.status == "Archived":
        abort(404)

    return render_template("report_detail.html", report=report)


# =========================================================
# CLAIM REQUEST
# =========================================================

@app.route("/report/<int:report_id>/claim", methods=["POST"])
def submit_claim(report_id):
    report = db.get_or_404(Report, report_id)

    if report.status in {"Returned", "Archived"}:
        flash(
            "This report is no longer accepting claim requests.",
            "warning"
        )
        return redirect(
            url_for("report_detail", report_id=report.id)
        )

    name = request.form.get("claimant_name", "").strip()
    student_id = request.form.get("student_or_staff_id", "").strip()
    contact = request.form.get("contact", "").strip()
    proof = request.form.get("proof", "").strip()

    if not all([name, contact, proof]):
        flash(
            "Please complete your name, contact method, and proof of ownership.",
            "warning"
        )
        return redirect(
            url_for("report_detail", report_id=report.id)
        )

    claim = Claim(
        report_id=report.id,
        claimant_name=name[:120],
        student_or_staff_id=student_id[:80] or None,
        contact=contact[:180],
        proof=proof[:2000],
    )

    report.status = "Pending Claim"
    db.session.add(claim)

    try:
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to save claim")
        flash(
            "Your claim could not be submitted. Please try again.",
            "danger"
        )
        return redirect(
            url_for("report_detail", report_id=report.id)
        )

    flash(
        "Claim request submitted to the administrator for verification.",
        "success"
    )

    return redirect(url_for("report_detail", report_id=report.id))


# =========================================================
# UPLOADED PHOTOS
# =========================================================

@app.route("/uploads/<path:filename>")
def uploaded_photo(filename):
    if not Report.query.filter_by(photo=filename).first():
        abort(404)

    if filename.startswith(("https://", "http://")):
        abort(404)

    return send_from_directory(str(UPLOAD_DIR), filename)


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        configured_user = os.environ.get("ADMIN_USERNAME", "")
        configured_password = os.environ.get("ADMIN_PASSWORD", "")

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            configured_user
            and configured_password
            and secrets.compare_digest(username, configured_user)
            and secrets.compare_digest(password, configured_password)
        ):
            session.clear()
            session["is_admin"] = True
            session.permanent = True

            flash("Welcome, administrator!", "success")
            return redirect(url_for("admin_dashboard"))

        flash(
            "Login failed. Check your credentials and Render Environment Variables.",
            "danger"
        )

    return render_template("admin_login.html")


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    claims = Claim.query.order_by(Claim.created_at.desc()).limit(6).all()

    stats = {
        "all": Report.query.filter(
            Report.status != "Archived"
        ).count(),
        "open": Report.query.filter_by(status="Open").count(),
        "claims": Claim.query.filter_by(status="Pending").count(),
        "returned": Report.query.filter_by(status="Returned").count(),
    }

    return render_template(
        "admin_dashboard.html",
        reports=reports,
        claims=claims,
        stats=stats,
    )


# =========================================================
# UPDATE REPORT STATUS
# =========================================================

@app.route(
    "/admin/report/<int:report_id>/status",
    methods=["POST"]
)
@admin_required
def update_report_status(report_id):
    report = db.get_or_404(Report, report_id)
    status = request.form.get("status", "")

    if status not in REPORT_STATUSES:
        abort(400)

    report.status = status

    try:
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to update report")
        flash(
            "Could not update this report. Please try again.",
            "danger"
        )
        return redirect(url_for("admin_dashboard"))

    flash(
        f'Report #{report.id} status updated to "{status}".',
        "success"
    )

    return redirect(url_for("admin_dashboard"))


# =========================================================
# DELETE REPORT
# =========================================================

@app.route(
    "/admin/report/<int:report_id>/delete",
    methods=["POST"]
)
@admin_required
def delete_report(report_id):
    report = db.get_or_404(Report, report_id)
    photo_name = report.photo

    db.session.delete(report)

    try:
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to delete report")
        flash(
            "Could not delete this report. Please try again.",
            "danger"
        )
        return redirect(url_for("admin_dashboard"))

    if photo_name and not photo_name.startswith(
        ("https://", "http://")
    ):
        try:
            (UPLOAD_DIR / photo_name).unlink(missing_ok=True)
        except OSError:
            app.logger.warning(
                "Could not remove photo file %s", photo_name
            )

    flash("Report and its claim requests deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# =========================================================
# ADMIN CLAIMS
# =========================================================

@app.route("/admin/claims")
@admin_required
def admin_claims():
    claims = Claim.query.order_by(Claim.created_at.desc()).all()

    return render_template(
        "admin_claims.html",
        claims=claims
    )


@app.route(
    "/admin/claim/<int:claim_id>/status",
    methods=["POST"]
)
@admin_required
def update_claim_status(claim_id):
    claim = db.get_or_404(Claim, claim_id)
    status = request.form.get("status", "")

    if status not in {"Pending", "Approved", "Rejected"}:
        abort(400)

    claim.status = status

    if status == "Approved":
        claim.report.status = "Returned"
    elif claim.report.status == "Pending Claim":
        claim.report.status = "Open"

    try:
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to update claim")
        flash(
            "Could not update this claim. Please try again.",
            "danger"
        )
        return redirect(url_for("admin_claims"))

    flash("Claim request updated.", "success")
    return redirect(url_for("admin_claims"))


# =========================================================
# EXPORT REPORTS TO CSV
# =========================================================

@app.route("/admin/export.csv")
@admin_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Type",
        "Item",
        "Category",
        "Description",
        "Location",
        "Date",
        "Status",
        "Reporter",
        "Private Contact",
        "Created At",
    ])

    reports = Report.query.order_by(
        Report.created_at.desc()
    ).all()

    for report in reports:
        writer.writerow([
            report.id,
            report.report_type,
            report.item_name,
            report.category,
            report.description,
            report.location,
            report.incident_date,
            report.status,
            report.contact_name or "",
            report.contact or "",
            report.created_at.isoformat(),
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=slsu_jge_findhub_reports.csv"
    )

    return response


# =========================================================
# LOGOUT
# =========================================================

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# =========================================================
# ERROR HANDLING AND SECURITY HEADERS
# =========================================================

@app.errorhandler(413)
def too_large(_error):
    return "Photo is too large. Please upload an image under 5 MB.", 413


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
