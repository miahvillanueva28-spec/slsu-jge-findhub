import base64
import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from hmac import compare_digest
from io import BytesIO

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename


# =============================================================================
# APP CONFIGURATION
# =============================================================================

app = Flask(_name_)

# On Render, DATABASE_URL should point to your PostgreSQL database.
# Locally, the fallback SQLite database is used.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///slsu_findhub.db"
)

# Compatibility for PostgreSQL connection strings.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql+psycopg://",
        1
    )

elif (
    DATABASE_URL.startswith("postgresql://")
    and "+psycopg" not in DATABASE_URL
):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://",
        "postgresql+psycopg://",
        1
    )


app.config.update(

    # IMPORTANT:
    # Set a strong SECRET_KEY in Render Environment Variables.
    SECRET_KEY=os.getenv(
        "SECRET_KEY",
        "CHANGE-THIS-SECRET-KEY"
    ),

    SQLALCHEMY_DATABASE_URI=DATABASE_URL,

    SQLALCHEMY_TRACK_MODIFICATIONS=False,

    # Maximum complete request size: 5 MB
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,

    # Session security
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv(
            "SESSION_COOKIE_SECURE",
            "true"
        ).lower() == "true"
    ),

    PERMANENT_SESSION_LIFETIME=3600,
)


db = SQLAlchemy(app)


# =============================================================================
# SLSU LOGO
# =============================================================================
#
# This is the official SLSU logo image currently used by the SLSU website.
# You can replace SLSU_LOGO_URL later with a campus-approved local image URL.
#

SLSU_LOGO_URL = os.getenv(
    "SLSU_LOGO_URL",
    "https://www.slsu.edu.ph/wp-content/uploads/2023/05/cropped-SLSU_Logo-1.png"
)


# =============================================================================
# ADMIN CREDENTIALS
# =============================================================================
#
# Set these in Render Environment Variables.
#
# ADMIN_USERNAME
# ADMIN_PASSWORD
#

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    "change-this-password"
)


# =============================================================================
# LIMITS / ALLOWED FILE TYPES
# =============================================================================

ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
}

MAX_ITEM_NAME = 120
MAX_CATEGORY = 80
MAX_LOCATION = 180
MAX_DESCRIPTION = 2500
MAX_NAME = 100
MAX_CONTACT = 150


# =============================================================================
# DATABASE MODEL
# =============================================================================

class Item(db.Model):

    _tablename_ = "items"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # LOST or FOUND
    item_type = db.Column(
        db.String(10),
        nullable=False
    )

    item_name = db.Column(
        db.String(MAX_ITEM_NAME),
        nullable=False
    )

    category = db.Column(
        db.String(MAX_CATEGORY),
        nullable=False
    )

    location = db.Column(
        db.String(MAX_LOCATION),
        nullable=False
    )

    item_date = db.Column(
        db.String(20),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    student_name = db.Column(
        db.String(MAX_NAME),
        nullable=False
    )

    contact = db.Column(
        db.String(MAX_CONTACT),
        nullable=False
    )

    # -------------------------------------------------------------------------
    # PHOTO STORAGE
    # -------------------------------------------------------------------------
    #
    # IMPORTANT:
    # The image is stored in the database instead of Render's temporary
    # filesystem. This allows the same photo to be available from another
    # device through the database.
    #

    image_data = db.Column(
        db.LargeBinary,
        nullable=True
    )

    image_mime = db.Column(
        db.String(50),
        nullable=True
    )

    image_filename = db.Column(
        db.String(180),
        nullable=True
    )

    # PENDING
    # ACTIVE
    # RESOLVED
    # HIDDEN
    #
    # There is intentionally NO delete route.
    #
    status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )


# Create tables when the application starts.
with app.app_context():
    db.create_all()


# =============================================================================
# ADMIN AUTHENTICATION
# =============================================================================

def admin_logged_in():
    return session.get(
        "admin_logged_in"
    ) is True


def admin_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if not admin_logged_in():

            return redirect(
                url_for(
                    "admin_login",
                    next=request.path
                )
            )

        return view(
            *args,
            **kwargs
        )

    return wrapped


# =============================================================================
# CSRF PROTECTION
# =============================================================================

def csrf_token():

    token = session.get(
        "csrf_token"
    )

    if not token:

        token = secrets.token_urlsafe(
            32
        )

        session["csrf_token"] = token

    return token


def valid_csrf(value):

    return (
        bool(value)
        and compare_digest(
            str(value),
            str(
                session.get(
                    "csrf_token",
                    ""
                )
            )
        )
    )


# =============================================================================
# GLOBAL TEMPLATE VARIABLES
# =============================================================================

@app.context_processor
def inject_globals():

    return {
        "slsu_logo": SLSU_LOGO_URL,
        "csrf": csrf_token,
    }


# =============================================================================
# SECURITY HEADERS
# =============================================================================

@app.after_request
def security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "SAMEORIGIN"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "img-src 'self' data: https://www.slsu.edu.ph; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "object-src 'none';"
    )

    return response


# =============================================================================
# PROFESSIONAL SLSU STYLE
# =============================================================================

BASE_STYLE = r"""
@import url(
    'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap'
);

:root {

    --deep-green: #062d22;
    --green: #087443;
    --green-light: #e8f5ee;

    --gold: #f3c74f;
    --cream: #f5f7f2;

    --white: #ffffff;

    --text: #17231e;
    --muted: #65736c;

    --line: #dfe7e2;

    --red: #b82c3c;

    --shadow:
        0 18px 50px
        rgba(
            16,
            51,
            38,
            .10
        );
}


* {
    box-sizing: border-box;
}


html {
    scroll-behavior: smooth;
}


body {

    margin: 0;

    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background:
        var(--cream);

    color:
        var(--text);

    line-height: 1.55;
}


a {
    text-decoration: none;
    color: inherit;
}


button,
input,
select,
textarea {
    font: inherit;
}


.container {

    width:
        min(
            1180px,
            calc(100% - 34px)
        );

    margin:
        0 auto;
}


/* ========================================================================= */
/* HEADER                                                                    */
/* ========================================================================= */

.topbar {

    position:
        sticky;

    top: 0;

    z-index: 100;

    background:
        linear-gradient(
            100deg,
            var(--deep-green),
            #0b4734
        );

    color: white;

    border-bottom:
        4px solid
        var(--gold);

    box-shadow:
        0 6px 22px
        rgba(0,0,0,.13);
}


.nav {

    min-height: 82px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 22px;
}


.brand {

    display: flex;

    align-items: center;

    gap: 14px;
}


.logo {

    width: 56px;
    height: 56px;

    object-fit: contain;

    border-radius: 50%;

    background:
        white;

    padding:
        4px;

    box-shadow:
        0 5px 15px
        rgba(0,0,0,.18);
}


.brand h1 {

    font-size:
        1.05rem;

    margin:
        0;

    font-weight:
        800;
}


.brand p {

    margin:
        2px 0 0;

    color:
        #d8eee4;

    font-size:
        .72rem;
}


.navlinks {

    display:
        flex;

    align-items:
        center;

    gap:
        7px;
}


.navlink {

    padding:
        9px 12px;

    border-radius:
        10px;

    color:
        #e8f6ef;

    font-weight:
        700;

    font-size:
        .82rem;
}


.navlink:hover {

    background:
        rgba(
            255,
            255,
            255,
            .09
        );

    color:
        white;
}


/* ========================================================================= */
/* HERO                                                                      */
/* ========================================================================= */

.hero {

    padding:
        52px 0 30px;
}


.hero-grid {

    display:
        grid;

    grid-template-columns:
        1.4fr .6fr;

    gap:
        24px;
}


.hero-card {

    position:
        relative;

    overflow:
        hidden;

    background:
        linear-gradient(
            135deg,
            #073326,
            #0d5b42
        );

    color:
        white;

    padding:
        38px;

    border-radius:
        28px;

    box-shadow:
        var(--shadow);
}


.hero-card::after {

    content:
        "";

    position:
        absolute;

    width:
        250px;

    height:
        250px;

    right:
        -120px;

    top:
        -100px;

    border:
        40px solid
        rgba(
            255,
            255,
            255,
            .05
        );

    border-radius:
        50%;
}


.kicker {

    display:
        inline-flex;

    align-items:
        center;

    color:
        var(--gold);

    font-size:
        .72rem;

    font-weight:
        800;

    letter-spacing:
        .17em;

    text-transform:
        uppercase;
}


.hero h2 {

    font-size:
        clamp(
            2.15rem,
            5vw,
            4rem
        );

    line-height:
        1.02;

    letter-spacing:
        -.055em;

    margin:
        12px 0 16px;
}


.hero p {

    max-width:
        700px;

    color:
        #d8eee4;
}


.hero-actions {

    display:
        flex;

    flex-wrap:
        wrap;

    gap:
        10px;

    margin-top:
        23px;
}


/* ========================================================================= */
/* STAT CARD                                                                 */
/* ========================================================================= */

.stat-card {

    background:
        white;

    border:
        1px solid
        var(--line);

    border-radius:
        28px;

    box-shadow:
        var(--shadow);

    padding:
        29px;

    display:
        flex;

    flex-direction:
        column;

    justify-content:
        center;
}


.stat-label {

    font-size:
        .75rem;

    font-weight:
        800;

    letter-spacing:
        .1em;

    color:
        var(--muted);

    text-transform:
        uppercase;
}


.stat-number {

    font-size:
        3.2rem;

    font-weight:
        800;

    color:
        var(--deep-green);

    line-height:
        1;

    margin:
        7px 0;
}


.stat-note {

    font-size:
        .82rem;

    color:
        var(--muted);
}


/* ========================================================================= */
/* BUTTONS                                                                   */
/* ========================================================================= */

.btn {

    display:
        inline-flex;

    align-items:
        center;

    justify-content:
        center;

    border:
        0;

    border-radius:
        12px;

    padding:
        12px 16px;

    cursor:
        pointer;

    font-weight:
        800;

    transition:
        .15s ease;
}


.btn-primary {

    background:
        var(--gold);

    color:
        #243018;
}


.btn-primary:hover {

    transform:
        translateY(-1px);
}


.btn-dark {

    background:
        var(--deep-green);

    color:
        white;
}


.btn-dark:hover {

    background:
        #0d5841;
}


.btn-light {

    background:
        #edf3ef;

    color:
        var(--deep-green);
}


.btn-small {

    padding:
        9px 11px;

    font-size:
        .76rem;
}


/* ========================================================================= */
/* PANELS                                                                    */
/* ========================================================================= */

.section {

    padding:
        16px 0 45px;
}


.panel {

    background:
        white;

    border:
        1px solid
        var(--line);

    border-radius:
        24px;

    box-shadow:
        var(--shadow);

    padding:
        28px;
}


.section-head {

    display:
        flex;

    align-items:
        end;

    justify-content:
        space-between;

    gap:
        18px;

    margin-bottom:
        22px;
}


.section-head h3 {

    margin:
        4px 0 0;

    font-size:
        1.55rem;

    letter-spacing:
        -.03em;
}


.section-head p {

    margin:
        5px 0 0;

    color:
        var(--muted);

    font-size:
        .9rem;
}


/* ========================================================================= */
/* BADGES                                                                    */
/* ========================================================================= */

.badge {

    display:
        inline-flex;

    align-items:
        center;

    padding:
        7px 10px;

    border-radius:
        999px;

    font-size:
        .68rem;

    font-weight:
        800;

    letter-spacing:
        .04em;
}


.badge-lost {

    background:
        #fff0f1;

    color:
        var(--red);
}


.badge-found {

    background:
        #e7f7ef;

    color:
        var(--green);
}


.badge-pending {

    background:
        #fff7df;

    color:
        #8a6900;
}


.badge-active {

    background:
        #e7f7ef;

    color:
        var(--green);
}


.badge-resolved {

    background:
        #edf1ef;

    color:
        #58665f;
}


.badge-hidden {

    background:
        #f0eff9;

    color:
        #5a4b91;
}


/* ========================================================================= */
/* FORM                                                                      */
/* ========================================================================= */

.form-grid {

    display:
        grid;

    grid-template-columns:
        repeat(
            2,
            minmax(
                0,
                1fr
            )
        );

    gap:
        16px;
}


.field {

    display:
        flex;

    flex-direction:
        column;

    gap:
        7px;
}


.field.full {

    grid-column:
        1 / -1;
}


.field label {

    font-size:
        .8rem;

    font-weight:
        800;
}


.field small {

    color:
        var(--muted);

    font-size:
        .72rem;
}


input,
select,
textarea {

    width:
        100%;

    border:
        1px solid
        #cfdad3;

    background:
        white;

    border-radius:
        12px;

    padding:
        12px 13px;

    color:
        var(--text);

    outline:
        none;
}


input:focus,
select:focus,
textarea:focus {

    border-color:
        var(--green);

    box-shadow:
        0 0 0 3px
        rgba(
            8,
            116,
            67,
            .1
        );
}


textarea {

    resize:
        vertical;

    min-height:
        132px;
}


input[type=file] {

    padding:
        10px;

    background:
        #fafcfb;
}


.form-foot {

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    gap:
        14px;

    margin-top:
        18px;

    flex-wrap:
        wrap;
}


.form-note {

    max-width:
        700px;

    font-size:
        .74rem;

    color:
        var(--muted);
}


/* ========================================================================= */
/* SEARCH                                                                    */
/* ========================================================================= */

.search-row {

    display:
        flex;

    flex-wrap:
        wrap;

    align-items:
        center;

    gap:
        9px;

    margin-bottom:
        18px;
}


.filter {

    border:
        1px solid
        var(--line);

    background:
        white;

    border-radius:
        999px;

    padding:
        9px 13px;

    font-size:
        .78rem;

    font-weight:
        800;

    cursor:
        pointer;
}


.filter.active {

    background:
        var(--deep-green);

    color:
        white;

    border-color:
        var(--deep-green);
}


.search-row input {

    max-width:
        360px;

    margin-left:
        auto;
}


/* ========================================================================= */
/* ITEM CARDS                                                                */
/* ========================================================================= */

.grid {

    display:
        grid;

    grid-template-columns:
        repeat(
            3,
            minmax(
                0,
                1fr
            )
        );

    gap:
        18px;
}


.item-card {

    background:
        white;

    border:
        1px solid
        var(--line);

    border-radius:
        20px;

    overflow:
        hidden;

    box-shadow:
        0 10px 34px
        rgba(
            16,
            51,
            38,
            .07
        );
}


.item-photo {

    width:
        100%;

    aspect-ratio:
        16 / 10;

    object-fit:
        cover;

    display:
        block;

    background:
        #eef3ef;
}


.no-photo {

    display:
        grid;

    place-items:
        center;

    color:
        #819087;

    font-weight:
        700;
}


.item-body {

    padding:
        17px;
}


.meta {

    display:
        flex;

    flex-wrap:
        wrap;

    gap:
        6px;

    margin-bottom:
        11px;
}


.item-body h4 {

    margin:
        0 0 5px;

    font-size:
        1.1rem;
}


.muted {

    color:
        var(--muted);

    font-size:
        .76rem;
}


.description {

    color:
        #506058;

    font-size:
        .83rem;

    margin-top:
        11px;

    white-space:
        pre-line;
}


.details {

    border-top:
        1px solid
        var(--line);

    padding-top:
        11px;

    margin-top:
        13px;

    display:
        grid;

    gap:
        5px;

    font-size:
        .75rem;

    color:
        #53625b;
}


.details b {

    color:
        #26362f;
}


/* ========================================================================= */
/* ALERTS                                                                    */
/* ========================================================================= */

.flash {

    padding:
        13px 15px;

    border-radius:
        13px;

    margin:
        18px 0;

    font-size:
        .82rem;

    font-weight:
        700;
}


.flash-success {

    background:
        #e8f7ef;

    color:
        #096a40;

    border:
        1px solid
        #bde4cf;
}


.flash-error {

    background:
        #fff0f1;

    color:
        #9b2733;

    border:
        1px solid
        #f2c5ca;
}


/* ========================================================================= */
/* ADMIN LOGIN                                                               */
/* ========================================================================= */

.auth-wrap {

    min-height:
        70vh;

    display:
        grid;

    place-items:
        center;

    padding:
        50px 0;
}


.auth-card {

    width:
        min(
            440px,
            100%
        );

    background:
        white;

    border:
        1px solid
        var(--line);

    border-radius:
        24px;

    box-shadow:
        var(--shadow);

    padding:
        30px;
}


.logo-lg {

    width:
        86px;

    height:
        86px;

    object-fit:
        contain;

    display:
        block;

    margin:
        0 auto 15px;
}


.auth-card h2 {

    text-align:
        center;

    margin:
        0;

    font-size:
        1.8rem;

    letter-spacing:
        -.04em;
}


.auth-card p {

    text-align:
        center;

    color:
        var(--muted);

    font-size:
        .82rem;
}


.stack {

    display:
        grid;

    gap:
        15px;

    margin-top:
        22px;
}


.back {

    display:
        block;

    text-align:
        center;

    margin-top:
        18px;

    font-size:
        .8rem;

    color:
        var(--green);

    font-weight:
        800;
}


/* ========================================================================= */
/* ADMIN DASHBOARD                                                           */
/* ========================================================================= */

.dashboard-head {

    display:
        flex;

    align-items:
        stretch;

    justify-content:
        space-between;

    gap:
        18px;

    margin:
        34px 0 20px;
}


.dashboard-title {

    flex:
        1;

    background:
        white;

    border:
        1px solid
        var(--line);

    border-radius:
        24px;

    box-shadow:
        var(--shadow);

    padding:
        29px;
}


.dashboard-title h2 {

    margin:
        5px 0 8px;

    font-size:
        2.2rem;

    letter-spacing:
        -.05em;
}


.dashboard-title p {

    margin:
        0;

    color:
        var(--muted);

    font-size:
        .84rem;
}


.dashboard-stat {

    width:
        210px;

    background:
        linear-gradient(
            135deg,
            #073326,
            #0d5b42
        );

    color:
        white;

    border-radius:
        24px;

    padding:
        26px;
}


.dashboard-stat .num {

    font-size:
        2.6rem;

    font-weight:
        800;

    line-height:
        1;
}


.dashboard-stat .lbl {

    margin-top:
        6px;

    font-size:
        .75rem;

    color:
        #d8eee4;
}


/* ========================================================================= */
/* ADMIN TABLE                                                               */
/* ========================================================================= */

.table-wrap {

    overflow:
        auto;
}


table {

    width:
        100%;

    min-width:
        1100px;

    border-collapse:
        collapse;
}


th,
td {

    text-align:
        left;

    vertical-align:
        top;

    padding:
        13px 11px;

    border-bottom:
        1px solid
        var(--line);

    font-size:
        .77rem;
}


th {

    color:
        #65736c;

    text-transform:
        uppercase;

    letter-spacing:
        .08em;

    font-size:
        .65rem;
}


.admin-thumb {

    width:
        84px;

    height:
        62px;

    object-fit:
        cover;

    border-radius:
        9px;

    background:
        #eef3ef;
}


.admin-desc {

    max-width:
        300px;

    color:
        #5a6761;

    white-space:
        pre-line;

    margin-top:
        7px;
}


.status-form {

    display:
        flex;

    gap:
        7px;

    align-items:
        center;
}


.status-form select {

    width:
        135px;

    padding:
        8px 9px;

    font-size:
        .75rem;
}


.small-note {

    font-size:
        .67rem;

    color:
        #89948e;

    margin-top:
        7px;
}


.no-delete {

    display:
        inline-flex;

    padding:
        5px 8px;

    border-radius:
        999px;

    background:
        #f2f5f3;

    color:
        #63726b;

    font-size:
        .64rem;

    font-weight:
        800;

    margin-top:
        6px;
}


/* ========================================================================= */
/* EMPTY                                                                     */
/* ========================================================================= */

.empty {

    padding:
        42px 20px;

    text-align:
        center;

    border:
        1px dashed
        #cfdad3;

    border-radius:
        17px;

    background:
        #fbfdfb;

    color:
        var(--muted);
}


/* ========================================================================= */
/* FOOTER                                                                    */
/* ========================================================================= */

.footer {

    margin-top:
        25px;

    background:
        var(--deep-green);

    color:
        #d7e8df;

    border-top:
        4px solid
        var(--gold);
}


.footer-in {

    padding:
        20px 0;

    display:
        flex;

    justify-content:
        space-between;

    gap:
        15px;

    flex-wrap:
        wrap;

    font-size:
        .72rem;
}


/* ========================================================================= */
/* RESPONSIVE                                                                */
/* ========================================================================= */

@media(max-width:900px) {

    .hero-grid,
    .grid {

        grid-template-columns:
            1fr;
    }


    .form-grid {

        grid-template-columns:
            1fr;
    }


    .field.full {

        grid-column:
            auto;
    }


    .dashboard-head {

        flex-direction:
            column;
    }


    .dashboard-stat {

        width:
            auto;
    }


    .search-row input {

        max-width:
            none;

        margin-left:
            0;
    }
}


@media(max-width:600px) {

    .container {

        width:
            min(
                100% - 20px,
                1180px
            );
    }


    .nav {

        min-height:
            72px;
    }


    .logo {

        width:
            48px;

        height:
            48px;
    }


    .brand h1 {

        font-size:
            .9rem;
    }


    .brand p {

        font-size:
            .62rem;
    }


    .navlinks {

        gap:
            2px;
    }


    .navlink {

        font-size:
            .68rem;

        padding:
            8px;
    }


    .hero {

        padding-top:
            28px;
    }


    .hero-card {

        padding:
            27px;
    }


    .panel {

        padding:
            20px;
    }


    .section-head {

        align-items:
            flex-start;

        flex-direction:
            column;
    }
}
"""


# =============================================================================
# BASE HTML
# =============================================================================

BASE_HTML = r"""
<!doctype html>

<html lang="en">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <meta
        name="theme-color"
        content="#062d22"
    >

    <meta
        name="description"
        content="SLSU JGE Tagkawayan Campus Lost and Found Portal"
    >

    <title>
        {{ title }} | SLSU FindHub
    </title>

    <style>
        {{ style|safe }}
    </style>

</head>


<body>


<header class="topbar">

    <div class="container nav">


        <a
            class="brand"
            href="{{ url_for('home') }}"
        >

            <img
                class="logo"
                src="{{ slsu_logo }}"
                alt="Southern Luzon State University logo"
            >


            <div>

                <h1>
                    SLSU FindHub
                </h1>

                <p>
                    JGE Tagkawayan Campus • Lost & Found Portal
                </p>

            </div>

        </a>


        <nav class="navlinks">

            <a
                class="navlink"
                href="{{ url_for('home') }}"
            >
                Home
            </a>


            {% if session.get('admin_logged_in') %}

                <a
                    class="navlink"
                    href="{{ url_for('admin_dashboard') }}"
                >
                    Admin Dashboard
                </a>


                <a
                    class="navlink"
                    href="{{ url_for('admin_logout') }}"
                >
                    Logout
                </a>

            {% else %}

                <a
                    class="navlink"
                    href="{{ url_for('admin_login') }}"
                >
                    Admin Login
                </a>

            {% endif %}

        </nav>

    </div>

</header>


<main class="container">


    {% with messages = get_flashed_messages(
        with_categories=true
    ) %}

        {% for category, message in messages %}

            <div
                class="
                    flash
                    {{
                        'flash-success'
                        if category == 'success'
                        else 'flash-error'
                    }}
                "
            >
                {{ message }}
            </div>

        {% endfor %}

    {% endwith %}


    {{ body|safe }}

</main>


<footer class="footer">

    <div class="container footer-in">

        <span>
            Southern Luzon State University – JGE Tagkawayan Campus
        </span>

        <span>
            SLSU FindHub • Campus Lost & Found
        </span>

    </div>

</footer>


</body>

</html>
"""


# =============================================================================
# HOME PAGE
# =============================================================================

HOME_BODY = r"""
<section class="hero">


    <div class="hero-grid">


        <div class="hero-card">


            <div class="kicker">
                SLSU JGE TAGKAWAYAN
            </div>


            <h2>
                A simple and secure way to report lost and found items.
            </h2>


            <p>
                Students do not need an account to post.
                Submit the item details, add a photo when available,
                and the report is saved to the central database
                for viewing on other devices.
            </p>


            <div class="hero-actions">


                <a
                    class="btn btn-primary"
                    href="#post"
                >
                    Post a Lost / Found Item
                </a>


                <a
                    class="btn btn-light"
                    href="#records"
                >
                    Browse Reports
                </a>


            </div>


        </div>


        <div class="stat-card">


            <div class="stat-label">
                Saved Reports
            </div>


            <div class="stat-number">
                {{ total }}
            </div>


            <div class="stat-note">
                Records remain in the database.
                The public website has no delete button.
            </div>


        </div>


    </div>


</section>



<!-- ====================================================================== -->
<!-- STUDENT FORM                                                           -->
<!-- ====================================================================== -->


<section
    class="section"
    id="post"



    <div class="panel">


        <div class="section-head">


            <div>

                <div
                    class="kicker"
                    style="color:var(--green)"
                >
                    STUDENT SUBMISSION
                </div>


                <h3>
                    Report a Lost or Found Item
                </h3>


                <p>
                    No student login required.
                </p>

            </div>


            <span class="badge badge-active">
                Central Database
            </span>


        </div>



        <form
            action="{{ url_for('submit_item') }}"
            method="post"
            enctype="multipart/form-data"
        >


            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf() }}"
            >


            <!-- Anti-bot honeypot -->

            <input
                type="text"
                name="website"
                tabindex="-1"
                autocomplete="off"
                style="
                    position:absolute;
                    left:-9999px;
                    opacity:0
                "
            >


            <div class="form-grid">


                <div class="field">

                    <label for="item_type">
                        Report Type
                    </label>


                    <select
                        id="item_type"
                        name="item_type"
                        required
                    >

                        <option value="">
                            Select report type
                        </option>

                        <option value="LOST">
                            Lost Item
                        </option>

                        <option value="FOUND">
                            Found Item
                        </option>

                    </select>

                </div>



                <div class="field">

                    <label for="item_name">
                        Item Name
                    </label>


                    <input
                        id="item_name"
                        name="item_name"
                        maxlength="120"
                        placeholder="e.g. Black wallet"
                        required
                    >

                </div>



                <div class="field">

                    <label for="category">
                        Category
                    </label>


                    <input
                        id="category"
                        name="category"
                        maxlength="80"
                        placeholder="e.g. ID, bag, phone, keys"
                        required
                    >

                </div>



                <div class="field">

                    <label for="location">
                        Location
                    </label>


                    <input
                        id="location"
                        name="location"
                        maxlength="180"
                        placeholder="Where was it lost or found?"
                        required
                    >

                </div>



                <div class="field">

                    <label for="item_date">
                        Date
                    </label>


                    <input
                        id="item_date"
                        name="item_date"
                        type="date"
                        required
                    >

                </div>



                <div class="field">

                    <label for="student_name">
                        Student Name
                    </label>


                    <input
                        id="student_name"
                        name="student_name"
                        maxlength="100"
                        placeholder="Your full name"
                        required
                    >

                </div>



                <div class="field full">

                    <label for="contact">
                        Contact Information
                    </label>


                    <input
                        id="contact"
                        name="contact"
                        maxlength="150"
                        placeholder="Messenger, email, or phone number"
                        required
                    >

                </div>



                <div class="field full">

                    <label for="description">
                        Description
                    </label>


                    <textarea
                        id="description"
                        name="description"
                        maxlength="2500"
                        placeholder="Add color, brand, identifying marks, or other useful details."
                        required
                    ></textarea>

                </div>



                <div class="field full">

                    <label for="photo">
                        Item Photo (optional)
                    </label>


                    <input
                        id="photo"
                        name="photo"
                        type="file"
                        accept="
                            image/jpeg,
                            image/png,
                            image/webp,
                            image/gif
                        "
                    >


                    <small>
                        JPG, PNG, WEBP, or GIF • Maximum 5 MB
                    </small>

                </div>


            </div>



            <div class="form-foot">


                <div class="form-note">

                    By submitting, you confirm that the information
                    is intended for the SLSU lost-and-found service.
                    Do not include passwords, bank details, or other
                    highly sensitive information.

                </div>


                <button
                    class="btn btn-dark"
                    type="submit"
                >
                    Submit Report
                </button>


            </div>


        </form>


    </div>


</section>



<!-- ====================================================================== -->
<!-- PUBLIC RECORDS                                                         -->
<!-- ====================================================================== -->


<section
    class="section"
    id="records"



    <div class="panel">


        <div class="section-head">


            <div>

                <div
                    class="kicker"
                    style="color:var(--green)"
                >
                    CAMPUS REPORTS
                </div>


                <h3>
                    Recent Lost & Found Items
                </h3>


                <p>
                    Search the saved reports below.
                </p>

            </div>


        </div>



        <div class="search-row">


            <button
                class="filter active"
                data-filter="ALL"
                type="button"
            >
                All
            </button>


            <button
                class="filter"
                data-filter="LOST"
                type="button"
            >
                Lost
            </button>


            <button
                class="filter"
                data-filter="FOUND"
                type="button"
            >
                Found
            </button>


            <input
                id="search"
                type="search"
                placeholder="Search item, category, or location..."
            >


        </div>



        {% if items %}


            <div
                class="grid"
                id="itemGrid"
            >


                {% for item in items %}


                    <article
                        class="item-card"
                        data-type="{{ item.item_type }}"
                        data-search="
                            {{
                                (
                                    item.item_name
                                    ~ ' '
                                    ~ item.category
                                    ~ ' '
                                    ~ item.location
                                    ~ ' '
                                    ~ item.description
                                )|lower
                            }}
                        "
                    >


                        {% if item.image_data %}


                            <a
                                href="{{ url_for(
                                    'item_image',
                                    item_id=item.id
                                ) }}"
                                target="_blank"
                                rel="noopener"
                            >


                                <img
                                    class="item-photo"
                                    src="{{ url_for(
                                        'item_image',
                                        item_id=item.id
                                    ) }}"
                                    alt="
                                        Photo of {{ item.item_name }}
                                    "
                                >


                            </a>


                        {% else %}


                            <div class="item-photo no-photo">
                                No photo uploaded
                            </div>


                        {% endif %}



                        <div class="item-body">


                            <div class="meta">


                                <span
                                    class="
                                        badge
                                        {{
                                            'badge-lost'
                                            if item.item_type == 'LOST'
                                            else 'badge-found'
                                        }}
                                    "
                                >
                                    {{ item.item_type }}
                                </span>


                                <span
                                    class="
                                        badge
                                        {{
                                            'badge-resolved'
                                            if item.status == 'RESOLVED'
                                            else 'badge-active'
                                        }}
                                    "
                                >
                                    {{ item.status }}
                                </span>


                            </div>



                            <h4>
                                {{ item.item_name }}
                            </h4>


                            <div class="muted">

                                {{ item.category }}
                                •
                                {{ item.item_date }}

                            </div>


                            <div class="description">

                                {{ item.description }}

                            </div>


                            <div class="details">


                                <div>
                                    <b>Location:</b>
                                    {{ item.location }}
                                </div>


                                <div>
                                    <b>Posted by:</b>
                                    {{ item.student_name }}
                                </div>


                                <div>
                                    <b>Contact:</b>
                                    {{ item.contact }}
                                </div>


                            </div>


                        </div>


                    </article>


                {% endfor %}


            </div>


            <div
                id="noResults"
                class="empty"
                style="display:none;margin-top:16px"
            >
                No reports match your search.
            </div>


        {% else %}


            <div class="empty">

                No reports yet.

                The first submitted item will appear here.

            </div>


        {% endif %}


    </div>


</section>



<script>

const filters =
    document.querySelectorAll(".filter");


const cards =
    document.querySelectorAll(".item-card");


const search =
    document.getElementById("search");


const noResults =
    document.getElementById("noResults");


let activeFilter =
    "ALL";


function applyFilters() {

    const query =
        (
            search?.value || ""
        )
        .trim()
        .toLowerCase();


    let shown =
        0;


    cards.forEach(
        card => {

            const typeOK =
                activeFilter === "ALL"
                ||
                card.dataset.type === activeFilter;


            const searchOK =
                !query
                ||
                card.dataset.search.includes(
                    query
                );


            const show =
                typeOK &&
                searchOK;


            card.style.display =
                show ? "" : "none";


            if (show) {

                shown++;

            }

        }
    );


    if (noResults) {

        noResults.style.display =
            shown ? "none" : "";

    }

}


filters.forEach(
    button => {

        button.addEventListener(
            "click",
            () => {

                filters.forEach(
                    b =>
                        b.classList.remove(
                            "active"
                        )
                );


                button.classList.add(
                    "active"
                );


                activeFilter =
                    button.dataset.filter;


                applyFilters();

            }
        );

    }
);


search?.addEventListener(
    "input",
    applyFilters
);

</script>
"""


# =============================================================================
# ADMIN LOGIN PAGE
# =============================================================================

LOGIN_BODY = r"""
<section class="auth-wrap">


    <div class="auth-card">


        <img
            class="logo-lg"
            src="{{ slsu_logo }}"
            alt="SLSU logo"
        >


        <div
            class="kicker"
            style="
                color:var(--green);
                justify-content:center
            "
        >
            RESTRICTED ACCESS
        </div>


        <h2>
            Administrator Login
        </h2>


        <p>
            Manage SLSU FindHub reports and update their status.
        </p>



        <form
            class="stack"
            method="post"
        >


            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf() }}"
            >


            <div class="field">


                <label for="username">
                    Username
                </label>


                <input
                    id="username"
                    name="username"
                    autocomplete="username"
                    required
                    autofocus
                >


            </div>



            <div class="field">


                <label for="password">
                    Password
                </label>


                <input
                    id="password"
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    required
                >


            </div>



            <button
                class="btn btn-dark"
                type="submit"
            >
                Sign In
            </button>


        </form>



        <a
            class="back"
            href="{{ url_for('home') }}"
        >
            ← Back to SLSU FindHub
        </a>


    </div>


</section>
"""


# =============================================================================
# ADMIN DASHBOARD
# =============================================================================

ADMIN_BODY = r"""
<section class="dashboard-head">


    <div class="dashboard-title">


        <div
            class="kicker"
            style="color:var(--green)"
        >
            SLSU FINDHUB ADMIN
        </div>


        <h2>
            Reports Dashboard
        </h2>


        <p>

            All student submissions are stored in the
            central database. This dashboard has no
            delete action.

            Use status changes to manage records
            without removing them.

        </p>


    </div>



    <div class="dashboard-stat">


        <div class="num">
            {{ total }}
        </div>


        <div class="lbl">
            Total saved records
        </div>


    </div>


</section>



<section class="section">


    <div class="panel">


        <div class="section-head">


            <div>

                <div
                    class="kicker"
                    style="color:var(--green)"
                >
                    RECORD MANAGEMENT
                </div>


                <h3>
                    All Student Reports
                </h3>


                <p>
                    Each record stays in the database
                    even after its status changes.
                </p>

            </div>


        </div>



        <div class="table-wrap">


            <table>


                <thead>


                    <tr>

                        <th>
                            ID
                        </th>

                        <th>
                            Photo
                        </th>

                        <th>
                            Report
                        </th>

                        <th>
                            Item Details
                        </th>

                        <th>
                            Student / Contact
                        </th>

                        <th>
                            Status
                        </th>

                    </tr>


                </thead>



                <tbody>


                {% for item in items %}


                    <tr>


                        <td>
                            #{{ item.id }}
                        </td>



                        <td>


                            {% if item.image_data %}


                                <a
                                    href="{{ url_for(
                                        'item_image',
                                        item_id=item.id
                                    ) }}"
                                    target="_blank"
                                    rel="noopener"
                                >


                                    <img
                                        class="admin-thumb"
                                        src="{{ url_for(
                                            'item_image',
                                            item_id=item.id
                                        ) }}"
                                        alt=""
                                    >


                                </a>


                            {% else %}


                                <span class="small-note">
                                    No photo
                                </span>


                            {% endif %}


                        </td>



                        <td>


                            <span
                                class="
                                    badge
                                    {{
                                        'badge-lost'
                                        if item.item_type == 'LOST'
                                        else 'badge-found'
                                    }}
                                "
                            >

                                {{ item.item_type }}

                            </span>


                            <div class="small-note">

                                {{ item.item_date }}

                            </div>


                        </td>



                        <td>


                            <strong>
                                {{ item.item_name }}
                            </strong>


                            <div class="small-note">
                                {{ item.category }}
                            </div>


                            <div class="small-note">

                                <b>Location:</b>
                                {{ item.location }}

                            </div>


                            <div class="admin-desc">

                                {{ item.description }}

                            </div>


                        </td>



                        <td>


                            <strong>
                                {{ item.student_name }}
                            </strong>


                            <div class="small-note">

                                {{ item.contact }}

                            </div>


                        </td>



                        <td>


                            <form
                                class="status-form"
                                action="{{ url_for(
                                    'admin_status',
                                    item_id=item.id
                                ) }}"
                                method="post"
                            >


                                <input
                                    type="hidden"
                                    name="csrf_token"
                                    value="{{ csrf() }}"
                                >


                                <select
                                    name="status"
                                >


                                    {% for status in [
                                        'PENDING',
                                        'ACTIVE',
                                        'RESOLVED',
                                        'HIDDEN'
                                    ] %}


                                        <option
                                            value="{{ status }}"
                                            {% if item.status == status %}
                                                selected
                                            {% endif %}
                                        >
                                            {{ status }}
                                        </option>


                                    {% endfor %}


                                </select>



                                <button
                                    class="btn btn-dark btn-small"
                                    type="submit"
                                >
                                    Save
                                </button>


                            </form>



                            <span class="no-delete">
                                Record cannot be deleted here
                            </span>


                        </td>


                    </tr>


                {% else %}


                    <tr>

                        <td colspan="6">


                            <div class="empty">

                                No reports have been
                                submitted yet.

                            </div>


                        </td>

                    </tr>


                {% endfor %}


                </tbody>


            </table>


        </div>


    </div>


</section>
"""


# =============================================================================
# PAGE RENDERER
# =============================================================================

def render_page(
    title,
    body_template,
    **context
):

    body = render_template_string(

        body_template,

        **context,

        slsu_logo=SLSU_LOGO_URL,

        csrf=csrf_token,
    )


    return render_template_string(

        BASE_HTML,

        title=title,

        body=body,

        style=BASE_STYLE,
    )


# =============================================================================
# HOME
# =============================================================================

@app.get("/")
def home():

    items = db.session.execute(

        db.select(Item)
        .where(
            Item.status != "HIDDEN"
        )
        .order_by(
            Item.created_at.desc()
        )

    ).scalars().all()


    return render_page(

        "Home",

        HOME_BODY,

        items=items,

        total=len(items),
    )


# =============================================================================
# STUDENT SUBMISSION
# =============================================================================

@app.post("/submit")
def submit_item():

    # -------------------------------------------------------------------------
    # Basic anti-bot check
    # -------------------------------------------------------------------------

    if request.form.get(
        "website",
        ""
    ).strip():

        return redirect(
            url_for("home")
        )


    # -------------------------------------------------------------------------
    # CSRF CHECK
    # -------------------------------------------------------------------------

    if not valid_csrf(
        request.form.get(
            "csrf_token"
        )
    ):

        flash(
            "Your form session expired. Please try again.",
            "error"
        )

        return redirect(
            url_for("home")
            + "#post"
        )


    # -------------------------------------------------------------------------
    # FORM DATA
    # -------------------------------------------------------------------------

    item_type = request.form.get(
        "item_type",
        ""
    ).strip().upper()


    item_name = request.form.get(
        "item_name",
        ""
    ).strip()


    category = request.form.get(
        "category",
        ""
    ).strip()


    location = request.form.get(
        "location",
        ""
    ).strip()


    item_date = request.form.get(
        "item_date",
        ""
    ).strip()


    description = request.form.get(
        "description",
        ""
    ).strip()


    student_name = request.form.get(
        "student_name",
        ""
    ).strip()


    contact = request.form.get(
        "contact",
        ""
    ).strip()


    errors = []


    # -------------------------------------------------------------------------
    # VALIDATION
    # -------------------------------------------------------------------------

    if item_type not in {
        "LOST",
        "FOUND"
    }:

        errors.append(
            "Please select Lost Item or Found Item."
        )


    if (
        not item_name
        or len(item_name) > MAX_ITEM_NAME
    ):

        errors.append(
            f"Item name is required and must be "
            f"{MAX_ITEM_NAME} characters or less."
        )


    if (
        not category
        or len(category) > MAX_CATEGORY
    ):

        errors.append(
            f"Category is required and must be "
            f"{MAX_CATEGORY} characters or less."
        )


    if (
        not location
        or len(location) > MAX_LOCATION
    ):

        errors.append(
            f"Location is required and must be "
            f"{MAX_LOCATION} characters or less."
        )


    if not item_date:

        errors.append(
            "Date is required."
        )


    if (
        not description
        or len(description) > MAX_DESCRIPTION
    ):

        errors.append(
            f"Description is required and must be "
            f"{MAX_DESCRIPTION} characters or less."
        )


    if (
        not student_name
        or len(student_name) > MAX_NAME
    ):

        errors.append(
            f"Student name is required and must be "
            f"{MAX_NAME} characters or less."
        )


    if (
        not contact
        or len(contact) > MAX_CONTACT
    ):

        errors.append(
            f"Contact information is required and must be "
            f"{MAX_CONTACT} characters or less."
        )


    # -------------------------------------------------------------------------
    # PHOTO
    # -------------------------------------------------------------------------

    photo = request.files.get(
        "photo"
    )


    image_data = None

    image_mime = None

    image_filename = None


    if photo and photo.filename:

        image_mime = (
            photo.mimetype
            or ""
        )


        image_filename = secure_filename(
            photo.filename
        )[:180]


        if image_mime not in ALLOWED_IMAGE_TYPES:

            errors.append(
                "Photo must be JPG, PNG, WEBP, or GIF."
            )

        else:

            image_data = photo.read()


            if len(image_data) > 5 * 1024 * 1024:

                errors.append(
                    "Photo must be 5 MB or smaller."
                )


    # -------------------------------------------------------------------------
    # ERROR RESPONSE
    # -------------------------------------------------------------------------

    if errors:

        for error in errors:

            flash(
                error,
                "error"
            )


        return redirect(
            url_for("home")
            + "#post"
        )


    # -------------------------------------------------------------------------
    # SAVE RECORD
    # -------------------------------------------------------------------------

    item = Item(

        item_type=item_type,

        item_name=item_name,

        category=category,

        location=location,

        item_date=item_date,

        description=description,

        student_name=student_name,

        contact=contact,

        image_data=image_data,

        image_mime=image_mime,

        image_filename=image_filename,

        status="PENDING",
    )


    db.session.add(
        item
    )


    db.session.commit()


    flash(
        "Report submitted successfully. "
        "The SLSU FindHub administrator can now review it.",
        "success"
    )


    return redirect(
        url_for("home")
        + "#records"
    )


# =============================================================================
# IMAGE VIEW
# =============================================================================

@app.get(
    "/image/<int:item_id>"
)
def item_image(item_id):

    item = db.session.get(
        Item,
        item_id
    )


    if (
        not item
        or not item.image_data
        or not item.image_mime
    ):

        abort(404)


    return send_file(

        BytesIO(
            item.image_data
        ),

        mimetype=
            item.image_mime,

        download_name=
            item.image_filename
            or "item-photo",

        max_age=3600,
    )


# =============================================================================
# API
# =============================================================================

@app.get(
    "/api/items"
)
def api_items():

    items = db.session.execute(

        db.select(Item)
        .order_by(
            Item.created_at.desc()
        )

    ).scalars().all()


    result = []


    for item in items:

        result.append({

            "id":
                item.id,

            "item_type":
                item.item_type,

            "item_name":
                item.item_name,

            "category":
                item.category,

            "location":
                item.location,

            "item_date":
                item.item_date,

            "description":
                item.description,

            "student_name":
                item.student_name,

            "contact":
                item.contact,

            "status":
                item.status,

            "has_image":
                bool(item.image_data),

            "image_url":
                (
                    url_for(
                        "item_image",
                        item_id=item.id
                    )
                    if item.image_data
                    else None
                ),

            "created_at":
                item.created_at.isoformat(),
        })


    return jsonify(
        result
    )


# =============================================================================
# ADMIN LOGIN
# =============================================================================

@app.route(
    "/admin/login",
    methods=[
        "GET",
        "POST"
    ]
)
def admin_login():

    if admin_logged_in():

        return redirect(
            url_for(
                "admin_dashboard"
            )
        )


    if request.method == "POST":


        # ---------------------------------------------------------------------
        # CSRF
        # ---------------------------------------------------------------------

        if not valid_csrf(
            request.form.get(
                "csrf_token"
            )
        ):

            flash(
                "Your login session expired. Please try again.",
                "error"
            )

            return redirect(
                url_for(
                    "admin_login"
                )
            )


        username = request.form.get(
            "username",
            ""
        ).strip()


        password = request.form.get(
            "password",
            ""
        )


        # ---------------------------------------------------------------------
        # LOGIN CHECK
        # ---------------------------------------------------------------------

        if (

            compare_digest(
                username,
                ADMIN_USERNAME
            )

            and

            compare_digest(
                password,
                ADMIN_PASSWORD
            )

        ):


            session.clear()


            session[
                "admin_logged_in"
            ] = True


            session[
                "admin_username"
            ] = username


            session[
                "csrf_token"
            ] = secrets.token_urlsafe(
                32
            )


            session.permanent = True


            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )


        flash(
            "Invalid administrator username or password.",
            "error"
        )


    return render_page(
        "Admin Login",
        LOGIN_BODY
    )


# =============================================================================
# ADMIN LOGOUT
# =============================================================================

@app.get(
    "/admin/logout"
)
def admin_logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# =============================================================================
# ADMIN DASHBOARD
# =============================================================================

@app.get(
    "/admin"
)
@admin_required
def admin_dashboard():

    items = db.session.execute(

        db.select(Item)
        .order_by(
            Item.created_at.desc()
        )

    ).scalars().all()


    return render_page(

        "Admin Dashboard",

        ADMIN_BODY,

        items=items,

        total=len(items),
    )


# =============================================================================
# ADMIN STATUS UPDATE
# =============================================================================
#
# IMPORTANT:
#
# There is deliberately NO delete route.
#
# Admin can only change status:
#
# PENDING
# ACTIVE
# RESOLVED
# HIDDEN
#
# The database record itself remains.
#
# =============================================================================

@app.post(
    "/admin/items/<int:item_id>/status"
)
@admin_required
def admin_status(item_id):

    if not valid_csrf(
        request.form.get(
            "csrf_token"
        )
    ):

        flash(
            "Your admin session expired. Please sign in again.",
            "error"
        )

        return redirect(
            url_for(
                "admin_login"
            )
        )


    item = db.session.get(
        Item,
        item_id
    )


    if not item:

        abort(404)


    status = request.form.get(
        "status",
        ""
    ).strip().upper()


    allowed = {
        "PENDING",
        "ACTIVE",
        "RESOLVED",
        "HIDDEN"
    }


    if status not in allowed:

        flash(
            "Invalid status.",
            "error"
        )

        return redirect(
            url_for(
                "admin_dashboard"
            )
        )


    # -------------------------------------------------------------------------
    # IMPORTANT:
    # Only update the status.
    #
    # The original record and photo stay in the database.
    # -------------------------------------------------------------------------

    item.status = status


    db.session.commit()


    flash(
        "Report status updated. "
        "The record remains saved in the database.",
        "success"
    )


    return redirect(
        url_for(
            "admin_dashboard"
        )
    )


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get(
    "/health"
)
def health():

    try:

        db.session.execute(
            db.text(
                "SELECT 1"
            )
        )


        return jsonify({

            "status":
                "ok",

            "database":
                "connected"

        })


    except Exception as exc:

        return jsonify({

            "status":
                "error",

            "database":
                str(exc)

        }), 500


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(413)
def file_too_large(_error):

    flash(
        "The uploaded request is too large. "
        "Maximum file size is 5 MB.",
        "error"
    )


    return redirect(
        url_for("home")
        + "#post"
    )


@app.errorhandler(404)
def page_not_found(_error):

    body = r"""
    <section class="auth-wrap">

        <div
            class="auth-card"
            style="text-align:center"
        >

            <div class="stat-number">
                404
            </div>


            <h2>
                Page Not Found
            </h2>


            <p>
                The page you requested
                could not be found.
            </p>


            <a
                class="btn btn-dark"
                href="{{ url_for('home') }}"
            >
                Back to FindHub
            </a>

        </div>

    </section>
    """


    return (
        render_page(
            "Page Not Found",
            body
        ),
        404
    )


@app.errorhandler(500)
def internal_error(_error):

    db.session.rollback()


    body = r"""
    <section class="auth-wrap">

        <div
            class="auth-card"
            style="text-align:center"
        >

            <div class="stat-number">
                500
            </div>


            <h2>
                Server Error
            </h2>


            <p>
                Something went wrong.
                Please try again later.
            </p>


            <a
                class="btn btn-dark"
                href="{{ url_for('home') }}"
            >
                Back to FindHub
            </a>

        </div>

    </section>
    """


    return (
        render_page(
            "Server Error",
            body
        ),
        500
    )


# =============================================================================
# START APPLICATION
# =============================================================================

if _name_ == "_main_":

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )


    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
