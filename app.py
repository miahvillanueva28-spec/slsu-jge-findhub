import os
import secrets
from pathlib import Path
from datetime import date, datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    flash, render_template_string, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

# ---------- CONFIGURATION ----------

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + str((DATA_DIR / "lost_found.db").resolve())
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

db = SQLAlchemy(app)
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}


# ---------- DATABASE ----------

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10), nullable=False)
    item_name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(180), nullable=False)
    incident_date = db.Column(db.String(10), nullable=False)
    contact = db.Column(db.String(160))
    photo = db.Column(db.String(255))
    status = db.Column(db.String(20), default="Open", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


# ---------- DESIGN ----------

STYLE = """
*{box-sizing:border-box}
body{margin:0;background:#f2f5f9;color:#172b40;
font-family:Arial,sans-serif;line-height:1.5}
header{background:#123b63;color:white;padding:18px}
nav,main{max-width:1100px;margin:auto}
nav{display:flex;justify-content:space-between;align-items:center;
gap:15px;flex-wrap:wrap}
nav a{color:white;text-decoration:none;font-weight:bold;margin-left:12px}
.brand{font-size:19px;font-weight:bold}
.sub{font-size:12px;color:#dbe9f6}
main{padding:24px 15px}
.hero,.panel,.card{background:white;border:1px solid #dce5ed;
border-radius:14px;overflow:hidden}
.hero,.panel{padding:22px;margin-bottom:22px}
h1,h2,h3{color:#153d65}
.hero h1{font-size:32px;margin-top:0}
.btn{display:inline-block;padding:10px 15px;border:0;border-radius:7px;
background:#205b91;color:white;text-decoration:none;cursor:pointer;
font-weight:bold}
.gold{background:#e4b547;color:#172b40}
.red{background:#b32d37}
input,select,textarea{width:100%;padding:11px;border:1px solid #ccd7e1;
border-radius:7px;font:inherit;margin:5px 0 15px}
textarea{min-height:100px}
label{font-weight:bold;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px}
.card img{width:100%;height:190px;object-fit:cover}
.cardbody{padding:15px;overflow-wrap:anywhere}
.tag{display:inline-block;background:#e3eef9;color:#205b91;
padding:4px 9px;border-radius:20px;font-size:12px;font-weight:bold}
.found{background:#e1f5e7;color:#23643a}
.muted{color:#687789;font-size:13px}
.flash{padding:12px;background:#e0f5e5;border-radius:7px;margin-bottom:12px}
.empty{padding:30px;background:white;border-radius:12px;text-align:center}
.filters{display:grid;grid-template-columns:1fr 1fr 2fr auto;gap:10px}
footer{text-align:center;color:#667789;padding:25px;font-size:12px}
@media(max-width:750px){.grid{grid-template-columns:repeat(2,1fr)}
.filters{grid-template-columns:1fr 1fr}}
@media(max-width:500px){.grid,.filters{grid-template-columns:1fr}
.hero h1{font-size:26px}nav a{margin-left:0}}
"""

def page(title, content, **values):
    template = """
    <!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} | SLSU JGE Lost and Found</title>
    <style>""" + STYLE + """</style></head><body>
    <header><nav>
    <div><div class="brand">SLSU JGE LOST & FOUND</div>
    <div class="sub">Tagkawayan Campus • Students and Staff</div></div>
    <div><a href="{{ url_for('home') }}">Home</a>
    <a href="{{ url_for('new_report') }}">Post Report</a>
    <a href="{{ url_for('admin_login') }}">Admin</a></div>
    </nav></header><main>
    {% with messages = get_flashed_messages() %}
    {% for message in messages %}<div class="flash">{{ message }}</div>
    {% endfor %}{% endwith %}
    """ + content + """
    </main><footer>SLSU JGE Tagkawayan Campus Lost and Found
    <br>Do not publish passwords or sensitive personal information.</footer>
    </body></html>
    """
    return render_template_string(template, title=title, **values)


# ---------- ADMIN PROTECTION ----------

def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            flash("Please log in as administrator.")
            return redirect(url_for("admin_login"))
        return function(*args, **kwargs)
    return wrapper


# ---------- HOME PAGE ----------

HOME = """
<section class="hero">
<h1>Lost something? Found an item?</h1>
<p>Help reunite lost belongings with their owners at Southern Luzon
State University, Judge Guillermo Eleazar (JGE), Tagkawayan Campus.</p>
<a class="btn gold" href="{{ url_for('new_report') }}">+ Post Lost or Found Item</a>
<p class="muted">No student or staff account is required.</p>
</section>

<h2>Browse Reports</h2>
<form method="get" class="filters">
<div><label>Type</label><select name="type">
<option value="">All</option>
<option value="Lost" {% if kind == 'Lost' %}selected{% endif %}>Lost</option>
<option value="Found" {% if kind == 'Found' %}selected{% endif %}>Found</option>
</select></div>
<div><label>Status</label><select name="status">
<option value="">All</option>
<option value="Open" {% if status == 'Open' %}selected{% endif %}>Open</option>
<option value="Resolved" {% if status == 'Resolved' %}selected{% endif %}>Resolved</option>
</select></div>
<div><label>Search item or location</label>
<input name="q" value="{{ q }}" placeholder="e.g. wallet, library"></div>
<div><label>&nbsp;</label><button class="btn">Search</button></div>
</form>

{% if reports %}
<div class="grid">
{% for r in reports %}
<article class="card">
{% if r.photo %}
<img src="{{ url_for('photo', filename=r.photo) }}" alt="Item photo">
{% endif %}
<div class="cardbody">
<span class="tag {% if r.report_type == 'Found' %}found{% endif %}">
{{ r.report_type }}</span>
<span class="tag">{{ r.status }}</span>
<h3>{{ r.item_name }}</h3>
<p>{{ r.description }}</p>
<p><b>Location:</b> {{ r.location }}</p>
<p><b>Date:</b> {{ r.incident_date }}</p>
{% if r.contact %}<p><b>Contact:</b> {{ r.contact }}</p>{% endif %}
<p class="muted">Posted {{ r.created_at.strftime('%b %d, %Y') }}</p>
</div></article>
{% endfor %}
</div>
{% else %}
<div class="empty">No matching reports yet.</div>
{% endif %}
"""

@app.route("/")
def home():
    query = Report.query

    kind = request.args.get("type", "")
    status = request.args.get("status", "")
    q = request.args.get("q", "").strip()

    if kind in ("Lost", "Found"):
        query = query.filter_by(report_type=kind)

    if status in ("Open", "Resolved"):
        query = query.filter_by(status=status)

    if q:
        term = f"%{q}%"
        query = query.filter(db.or_(
            Report.item_name.ilike(term),
            Report.location.ilike(term),
            Report.description.ilike(term)
        ))

    reports = query.order_by(Report.created_at.desc()).all()

    return page("Home", HOME, reports=reports, kind=kind,
                status=status, q=q)


# ---------- POST A REPORT ----------

FORM = """
<section class="panel">
<h2>Submit a Lost or Found Report</h2>
<p class="muted">Fields marked * are required.</p>
<form method="post" enctype="multipart/form-data">
<label>Report Type *</label>
<select name="report_type" required>
<option value="">Select</option>
<option value="Lost">I lost an item</option>
<option value="Found">I found an item</option>
</select>

<label>Item Name *</label>
<input name="item_name" maxlength="120" required
placeholder="Example: black wallet">

<label>Description *</label>
<textarea name="description" maxlength="2000" required
placeholder="Describe the item and its appearance"></textarea>

<label>Where was it lost or found? *</label>
<input name="location" maxlength="180" required
placeholder="Example: library, classroom, canteen">

<label>Date Lost or Found *</label>
<input name="incident_date" type="date" max="{{ today }}" required>

<label>Contact Information (optional)</label>
<input name="contact" maxlength="160"
placeholder="School email or preferred contact method">
<p class="muted">Contact information will be visible publicly.</p>

<label>Upload Item Photo (optional)</label>
<input type="file" name="photo"
accept=".jpg,.jpeg,.png,.webp" >
<p class="muted">JPG, PNG, or WEBP. Maximum 5 MB.</p>

<button class="btn gold" type="submit">Submit Report</button>
<a class="btn" href="{{ url_for('home') }}">Cancel</a>
</form></section>
"""

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )

@app.route("/report/new", methods=["GET", "POST"])
def new_report():
    if request.method == "POST":
        kind = request.form.get("report_type", "")
        name = request.form.get("item_name", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        incident_date = request.form.get("incident_date", "")
        contact = request.form.get("contact", "").strip()

        if not all([kind, name, description, location, incident_date]):
            flash("Please complete all required fields.")
            return redirect(url_for("new_report"))

        if kind not in ("Lost", "Found"):
            abort(400)

        try:
            parsed_date = date.fromisoformat(incident_date)
            if parsed_date > date.today():
                raise ValueError
        except ValueError:
            flash("Please enter a valid date that is not in the future.")
            return redirect(url_for("new_report"))

        filename = None
        uploaded = request.files.get("photo")

        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                flash("Only JPG, JPEG, PNG, and WEBP images are allowed.")
                return redirect(url_for("new_report"))

            secure_filename(uploaded.filename)
            extension = uploaded.filename.rsplit(".", 1)[1].lower()
            filename = secrets.token_hex(16) + "." + extension
            uploaded.save(UPLOAD_DIR / filename)

        report = Report(
            report_type=kind,
            item_name=name[:120],
            description=description[:2000],
            location=location[:180],
            incident_date=incident_date,
            contact=contact[:160] or None,
            photo=filename
        )

        db.session.add(report)
        db.session.commit()

        flash("Your report has been submitted successfully!")
        return redirect(url_for("home"))

    return page("Post Report", FORM, today=date.today().isoformat())


# ---------- SERVE PHOTOS ----------

@app.route("/uploads/<path:filename>")
def photo(filename):
    if not Report.query.filter_by(photo=filename).first():
        abort(404)
    return send_from_directory(str(UPLOAD_DIR), filename)


# ---------- ADMIN LOGIN ----------

LOGIN = """
<section class="panel">
<h2>Administrator Login</h2>
<form method="post">
<label>Username</label>
<input name="username" required autocomplete="username">
<label>Password</label>
<input name="password" type="password" required
autocomplete="current-password">
<button class="btn" type="submit">Log In</button>
</form>
<p class="muted">Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH
in Render Environment Variables.</p>
</section>
"""

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = os.environ.get("ADMIN_USERNAME", "")
        password_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
        entered_user = request.form.get("username", "")
        entered_password = request.form.get("password", "")

        if (
            username
            and password_hash
            and secrets.compare_digest(entered_user, username)
        ):
            try:
                valid = check_password_hash(password_hash, entered_password)
            except (ValueError, TypeError):
                valid = False

            if valid:
                session.clear()
                session["admin"] = True
                session.permanent = True
                return redirect(url_for("dashboard"))

        flash("Invalid login or admin credentials are not configured.")

    return page("Admin Login", LOGIN)


# ---------- ADMIN DASHBOARD ----------

DASHBOARD = """
<h2>Administrator Dashboard</h2>
<p>Only the administrator can update or delete reports.</p>
<p><a class="btn" href="{{ url_for('logout') }}">Log Out</a></p>

{% if reports %}
<div class="grid">
{% for r in reports %}
<article class="card">
{% if r.photo %}
<img src="{{ url_for('photo', filename=r.photo) }}" alt="Item photo">
{% endif %}
<div class="cardbody">
<span class="tag">{{ r.report_type }}</span>
<h3>{{ r.item_name }}</h3>
<p>{{ r.description }}</p>
<p><b>Location:</b> {{ r.location }}</p>
<p><b>Date:</b> {{ r.incident_date }}</p>
<p><b>Contact:</b> {{ r.contact or 'Not provided' }}</p>

<form method="post" action="{{ url_for('update_status', report_id=r.id) }}">
<label>Status</label>
<select name="status">
<option value="Open" {% if r.status == 'Open' %}selected{% endif %}>Open</option>
<option value="Resolved" {% if r.status == 'Resolved' %}selected{% endif %}>Resolved / Returned</option>
</select>
<button class="btn" type="submit">Update Status</button>
</form>

<form method="post" action="{{ url_for('delete_report', report_id=r.id) }}"
onsubmit="return confirm('Permanently delete this report?')">
<button class="btn red" type="submit">Delete Report</button>
</form>
</div></article>
{% endfor %}
</div>
{% else %}
<div class="empty">No reports submitted yet.</div>
{% endif %}
"""

@app.route("/admin")
@admin_required
def dashboard():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return page("Admin Dashboard", DASHBOARD, reports=reports)


@app.route("/admin/status/<int:report_id>", methods=["POST"])
@admin_required
def update_status(report_id):
    report = db.get_or_404(Report, report_id)
    status = request.form.get("status")

    if status in ("Open", "Resolved"):
        report.status = status
        db.session.commit()
        flash("Report status updated.")

    return redirect(url_for("dashboard"))


@app.route("/admin/delete/<int:report_id>", methods=["POST"])
@admin_required
def delete_report(report_id):
    report = db.get_or_404(Report, report_id)

    if report.photo:
        try:
            (UPLOAD_DIR / report.photo).unlink(missing_ok=True)
        except OSError:
            pass

    db.session.delete(report)
    db.session.commit()
    flash("Report deleted by administrator.")
    return redirect(url_for("dashboard"))


@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.errorhandler(413)
def file_too_large(error):
    return "Image exceeds 5 MB. Please upload a smaller image.", 413


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
