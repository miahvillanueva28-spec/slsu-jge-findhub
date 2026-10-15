import os
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATA_DIR = os.environ.get("DATA_DIR", "/tmp/slsu_lost_found")
os.makedirs(DATA_DIR, exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///" + os.path.join(DATA_DIR, "lost_found.db")
).replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

db = SQLAlchemy(app)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10), nullable=False)  # Lost / Found
    item_name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(180), nullable=False)
    incident_date = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(60), nullable=False)
    image_filename = db.Column(db.String(255))
    contact_name = db.Column(db.String(100), nullable=False)
    contact_method = db.Column(db.String(180), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please sign in with the administrator account.", "error")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    kind = request.args.get("type", "All")
    category = request.args.get("category", "All")
    search = request.args.get("q", "").strip()
    query = Report.query
    if kind in ("Lost", "Found"):
        query = query.filter_by(report_type=kind)
    if category and category != "All":
        query = query.filter_by(category=category)
    if search:
        term = f"%{search}%"
        query = query.filter(
            db.or_(Report.item_name.ilike(term), Report.description.ilike(term),
                   Report.location.ilike(term))
        )
    reports = query.order_by(Report.created_at.desc()).all()
    return render_template("index.html", reports=reports, kind=kind, category=category, search=search)

@app.route("/report", methods=["GET", "POST"])
def create_report():
    if request.method == "POST":
        report_type = request.form.get("report_type", "")
        item_name = request.form.get("item_name", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        incident_date = request.form.get("incident_date", "").strip()
        category = request.form.get("category", "").strip()
        contact_name = request.form.get("contact_name", "").strip()
        contact_method = request.form.get("contact_method", "").strip()
        image = request.files.get("image")

        if report_type not in ("Lost", "Found"):
            flash("Choose whether the item was lost or found.", "error")
        elif not all([item_name, description, location, incident_date, category, contact_name, contact_method]):
            flash("Please complete all required fields.", "error")
        elif len(item_name) > 120 or len(location) > 180 or len(contact_method) > 180:
            flash("One or more fields are too long. Please shorten them.", "error")
        elif image and image.filename and not allowed_file(image.filename):
            flash("Upload an image file (PNG, JPG, JPEG, GIF, or WEBP).", "error")
        else:
            filename = None
            if image and image.filename:
                safe_name = secure_filename(image.filename)
                suffix = Path(safe_name).suffix.lower()
                filename = f"{secrets.token_hex(16)}{suffix}"
                image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            report = Report(
                report_type=report_type, item_name=item_name, description=description,
                location=location, incident_date=incident_date, category=category,
                image_filename=filename, contact_name=contact_name, contact_method=contact_method
            )
            db.session.add(report)
            db.session.commit()
            flash("Your report has been posted. Thank you for helping the SLSU Tagkawayan community!", "success")
            return redirect(url_for("index"))
    return render_template("report.html")

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # Uploads are stored in DATA_DIR. On Render Free, local files are temporary.
    from flask import send_from_directory
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = os.environ.get("ADMIN_USERNAME", "")
        password_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
        supplied_user = request.form.get("username", "")
        supplied_password = request.form.get("password", "")
        if username and password_hash and supplied_user == username and check_password_hash(password_hash, supplied_password):
            session.clear()
            session["is_admin"] = True
            session["admin_username"] = username
            flash("You are signed in.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid administrator username or password.", "error")
    return render_template("admin_login.html")

@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("index"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template("admin.html", reports=reports)

@app.route("/admin/delete/<int:report_id>", methods=["POST"])
@admin_required
def delete_report(report_id):
    report = db.get_or_404(Report, report_id)
    if report.image_filename:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], report.image_filename))
        except FileNotFoundError:
            pass
    db.session.delete(report)
    db.session.commit()
    flash(f'Report #{report_id} was deleted by the administrator.', "success")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(413)
def too_large(_error):
    flash("Image is too large. Maximum upload size is 5 MB.", "error")
    return redirect(url_for("create_report"))

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
