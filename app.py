import re
import os
from datetime import datetime, timedelta
from pathlib import Path

from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_cors import CORS
from flask_login import LoginManager, login_user, login_required, current_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
REDIS_URL = "redis://default:ySETjuEBUosMjMdibVxUkCjbGnKiUAJm@redis.railway.internal:6379"
from sqlalchemy import create_engine, select, Column, Integer, String, Date, Boolean, Text, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, scoped_session
from dotenv import load_dotenv
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message
import smtplib
from email.utils import formataddr
from flask import abort

import csv
from logging.handlers import RotatingFileHandler
import logging

# Optional: OpenCV for QR decode from uploaded image (verify by image)
try:
    import cv2
except Exception:
    cv2 = None

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "pharma.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")

# --- Audit Logging ---
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
log_path = LOG_DIR / "app.log"
handler = RotatingFileHandler(log_path, maxBytes=512000, backupCount=3)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
handler.setFormatter(formatter)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

# --- Rate Limiting ---
REDIS_URL = "redis://default:ySETjuEBUosMjMdibVxUkCjbGnKiUAJm@redis.railway.internal:6379"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=REDIS_URL,
    default_limits=[
        os.getenv("DEFAULT_HOURLY_LIMIT", "200 per hour"),
        os.getenv("DEFAULT_MINUTE_LIMIT", "50 per minute")
    ]
)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key")

# Mail configuration
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=os.getenv("MAIL_USE_TLS", "True").lower() == "true",
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME"))
)
mail = Mail(app)

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# CORS
origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]
CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)

# Database (SQLAlchemy)
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False))
Base = declarative_base()

ROLE_USER = "USER"
ROLE_COMPANY = "COMPANY"
ROLE_ADMIN = "ADMIN"

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default=ROLE_USER)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    company_profile = relationship("CompanyProfile", back_populates="user", uselist=False)
    def get_id(self): return str(self.id)
    @property
    def is_admin(self):
        return self.role == 'ADMIN'


class CompanyProfile(Base):
    __tablename__ = "company_profiles"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    company_name = Column(String(255), nullable=False)
    owner_name = Column(String(255), nullable=False)
    cnic = Column(String(50), nullable=False)
    cert_no = Column(String(100), nullable=False)
    cert_image = Column(String(255), nullable=True)  # stored filename
    approved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="company_profile")
    medicines = relationship(
        "Medicine",
        back_populates="company",
        cascade="all, delete-orphan"
    )

class Medicine(Base):
    __tablename__ = "medicines"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("company_profiles.id"), nullable=False)
    name = Column(String(255), nullable=False)
    formula = Column(Text, nullable=True)
    approved_date = Column(Date, nullable=True)
    expiry_date = Column(Date, nullable=True)
    batch_no = Column(String(100), unique=True, nullable=False)
    qr_image = Column(String(255), nullable=True)  # stored filename
    created_at = Column(DateTime, default=datetime.utcnow)

    company = relationship("CompanyProfile", back_populates="medicines")




class SearchLog(Base):
    __tablename__ = "search_logs"
    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("company_profiles.id"), nullable=True)
    term = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    company = relationship("CompanyProfile")

class VerificationLog(Base):
    __tablename__ = "verification_logs"
    id = Column(Integer, primary_key=True)
    medicine_id = Column(Integer, ForeignKey("medicines.id"), nullable=True)
    company_id = Column(Integer, ForeignKey("company_profiles.id"), nullable=True)
    batch_no = Column(String(100), nullable=True)
    ip = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Recall(Base):
    __tablename__ = "recalls"
    id = Column(Integer, primary_key=True)
    medicine_id = Column(Integer, ForeignKey("medicines.id"), nullable=False, unique=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# --- Create tables & lightweight migrations (SQLAlchemy 2.0 safe) ---
with engine.connect() as conn:
    # Ensure tables exist
    Base.metadata.create_all(engine)

    # Users: add email_verified if missing
    cols_users = [c["name"] for c in conn.exec_driver_sql("PRAGMA table_info(users)").mappings()]
    if "email_verified" not in cols_users:
        conn.exec_driver_sql("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0")

    # Medicines: add expiry_date if missing
    cols_meds = [c["name"] for c in conn.exec_driver_sql("PRAGMA table_info(medicines)").mappings()]
    if "expiry_date" not in cols_meds:
        conn.exec_driver_sql("ALTER TABLE medicines ADD COLUMN expiry_date DATE")

# Auth
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    with SessionLocal() as db:
        return db.get(User, int(user_id))

def init_admin():
    email = os.getenv("ADMIN_EMAIL", "admin@verifypharma.com")
    pwd = os.getenv("ADMIN_PASSWORD", "admin123")
    with SessionLocal() as db:
        existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if not existing:
            admin = User(email=email, password_hash=generate_password_hash(pwd), role=ROLE_ADMIN)
            db.add(admin)
            db.commit()
init_admin()

# Helpers
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file_storage):
    if not file_storage: return None
    filename = secure_filename(file_storage.filename or "")
    if not filename: return None
    dest = UPLOAD_DIR / filename
    base, ext = os.path.splitext(filename)
    i = 1
    while dest.exists():
        filename = f"{base}_{i}{ext}"
        dest = UPLOAD_DIR / filename
        i += 1
    file_storage.save(dest)
    return filename

# --- Email helpers ---
def send_email(subject, recipients, body, html=None):
    try:
        msg = Message(subject=subject, recipients=recipients, body=body, html=html)
        mail.send(msg)
        app.logger.info(f"Email sent to {recipients}")
        return True
    except Exception as e:
        app.logger.warning(f"Flask-Mail send failed: {e}. Attempting SMTP fallback.")
        try:
            from email.mime.text import MIMEText
            m = MIMEText(html or body, 'html' if html else 'plain', 'utf-8')
            m['Subject'] = subject
            m['From'] = app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
            m['To'] = ",".join(recipients)
            with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as s:
                if app.config.get('MAIL_USE_TLS'): s.starttls()
                if app.config.get('MAIL_USERNAME'): s.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                s.sendmail(m['From'], recipients, m.as_string())
            return True
        except Exception as e2:
            app.logger.error(f"SMTP send failed: {e2}")
            return False

def generate_token(email):
    return serializer.dumps(email)

def confirm_token(token, max_age=3600*24):
    email = serializer.loads(token, max_age=max_age)
    return email

def decode_qr_image(path):
    if cv2 is None:
        return None, "OpenCV not installed"
    img = cv2.imread(str(path))
    if img is None:
        return None, "Invalid image"
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    if data:
        return data, None
    return None, "No QR detected"

# Routes
@app.get("/")
def index():
    return render_template("index.html")

def is_strong_password(pwd: str) -> bool:
    if not pwd or len(pwd) < 8: return False
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(c in r"!@#$%^&*()-_=+[]{}\|;:'\",.<>/?`~" for c in pwd)
    return has_upper and has_lower and has_digit and has_special

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":

        role = request.form.get("role", ROLE_USER)
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("signup"))
        with SessionLocal() as db:
            exists = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if exists:
                flash("This email is already registered. Please login instead.", "warning")
                return redirect(url_for("login"))
            user = User(email=email, password_hash=generate_password_hash(password), role=role, email_verified=False)
            db.add(user); db.commit()
            try:
                token = generate_token(email)
                verify_link = url_for('verify_email', token=token, _external=True)
                send_email("Verify your email", [email], f"Click to verify: {verify_link}", html=f"<p>Please verify your email:</p><p><a href='{verify_link}'>Verify Email</a></p>")
                flash("Signup successful. Check your email for verification link.", "success")
            except Exception as e:
                app.logger.error(f"Verification email failed: {e}")
                flash("Signup successful. Could not send verification email, contact support.", "warning")
            return redirect(url_for("login"))
    return render_template("signup.html")

@limiter.limit("10 per minute")
@app.get('/verify-email')
def verify_email():
    token = request.args.get('token')
    if not token: abort(400)
    try:
        email = confirm_token(token)
    except SignatureExpired:
        flash('Verification link expired. Please sign in and request a new link.', 'danger')
        return redirect(url_for('login'))
    except BadSignature:
        flash('Invalid verification link.', 'danger')
        return redirect(url_for('login'))
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.email==email)).scalar_one_or_none()
        if not user:
            flash('User not found.', 'danger'); return redirect(url_for('login'))
        user.email_verified = True; db.commit()
    flash('Email verified. You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":

        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        with SessionLocal() as db:
            user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if user and check_password_hash(user.password_hash, password):
                if user.role != ROLE_ADMIN and not getattr(user, 'email_verified', False):
                    flash('Please verify your email before logging in.', 'warning')
                    return redirect(url_for('login'))
                login_user(user); flash("Logged in.", "success")
                return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.get("/company/medicines/bulk")
@login_required
def company_bulk_upload_form():
    if current_user.role != ROLE_COMPANY:
        return jsonify({"ok": False}), 403
    return render_template("company_bulk_upload.html")

@app.post("/company/medicines/bulk")
@login_required
def company_bulk_upload():
    if current_user.role != ROLE_COMPANY:
        return jsonify({"ok": False}), 403
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".csv"):
        flash("Please upload a CSV file.", "danger")
        return redirect(url_for("company_bulk_upload_form"))
    filename = save_upload(file)
    count = 0
    errors = 0
    with SessionLocal() as db:
        profile = db.execute(select(CompanyProfile).where(CompanyProfile.user_id==current_user.id)).scalar_one_or_none()
        if not profile:
            flash("Company profile not found.", "danger")
            return redirect(url_for("dashboard"))
        path = UPLOAD_DIR / filename
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    name = (row.get("name") or "").strip()
                    batch_no = (row.get("batch_no") or "").strip()
                    if not name or not batch_no:
                        errors += 1
                        continue
                    formula = (row.get("formula") or "").strip() or None
                    approved_date = (row.get("approved_date") or "").strip() or None
                    expiry_date = (row.get("expiry_date") or "").strip() or None
                    ad = datetime.strptime(approved_date, "%Y-%m-%d").date() if approved_date else None
                    ed = datetime.strptime(expiry_date, "%Y-%m-%d").date() if expiry_date else None
                    m = Medicine(company_id=profile.id, name=name, formula=formula, batch_no=batch_no, approved_date=ad)
                    # set expiry_date directly (column ensured by migration above)
                    m.expiry_date = ed
                    db.add(m)
                    count += 1
                except Exception:
                    errors += 1
            db.commit()
    flash(f"Bulk upload complete. {count} rows added, {errors} errors.", "success")
    return redirect(url_for("company_medicines"))

@app.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", role=current_user.role)

# Company registration & approval
@app.route("/company/register", methods=["GET","POST"])
@login_required
def company_register():
    if current_user.role != ROLE_COMPANY:
        flash("Only companies can register company details.", "danger")
        return redirect(url_for("dashboard"))
    with SessionLocal() as db:
        profile = db.execute(select(CompanyProfile).where(CompanyProfile.user_id == current_user.id)).scalar_one_or_none()
        if request.method == "POST":

            company_name = request.form.get("company_name","").strip()
            owner_name = request.form.get("owner_name","").strip()
            cnic = request.form.get("cnic","").strip()
            if not re.match(r"^\d{5}-\d{7}-\d$", cnic or ""):
                flash("CNIC format invalid. Use 12345-1234567-1", "danger")
                return render_template("company_register.html")
            cert_no = request.form.get("cert_no","").strip()
            cert_file = request.files.get("cert_image")
            cert_filename = save_upload(cert_file)
            if profile:
                profile.company_name = company_name
                profile.owner_name = owner_name
                profile.cnic = cnic
                profile.cert_no = cert_no
                if cert_filename: profile.cert_image = cert_filename
            else:
                profile = CompanyProfile(
                    user_id=current_user.id, company_name=company_name, owner_name=owner_name,
                    cnic=cnic, cert_no=cert_no, cert_image=cert_filename, approved=False
                )
                db.add(profile)
            db.commit()
            flash("Submitted for admin approval.", "success")
            return redirect(url_for("dashboard"))
        return render_template("company_register.html", profile=profile)

@app.get("/admin/companies")
@login_required
def admin_companies():
    if current_user.role != ROLE_ADMIN:
        flash("Admin only.", "danger")
        return redirect(url_for("dashboard"))
    with SessionLocal() as db:
        companies = db.query(CompanyProfile).order_by(CompanyProfile.created_at.desc()).all()
    return render_template("admin_companies.html", companies=companies)

@app.post("/admin/companies/<int:cid>/approve")
@login_required
def approve_company(cid):
    if current_user.role != ROLE_ADMIN:
        return jsonify({"ok": False}), 403
    with SessionLocal() as db:
        c = db.get(CompanyProfile, cid)
        if not c:
            return jsonify({"ok": False}), 404
        c.approved = True
        db.commit()
        try:
            send_email('Company Approved', [c.user.email], f'Your company {c.company_name} has been approved.')
        except Exception as e:
            app.logger.warning(f'Approval email failed: {e}')
    app.logger.info(f"Admin {current_user.id} approved company {cid}")
    return redirect(url_for("admin_companies"))

@app.post("/admin/companies/<int:cid>/delete")
@login_required
def delete_company(cid):
    if current_user.role != ROLE_ADMIN:
        return jsonify({"ok": False}), 403
    with SessionLocal() as db:
        c = db.get(CompanyProfile, cid)
        if not c:
            return jsonify({"ok": False}), 404
        db.delete(c)
        db.commit()
    app.logger.info(f"Admin {current_user.id} deleted company {cid}")
    return redirect(url_for("admin_companies"))

# Company medicines CRUD
@app.route("/company/medicines", methods=["GET","POST"])
@login_required
def company_medicines():
    if current_user.role != ROLE_COMPANY:
        flash("Only companies can manage medicines.", "danger")
        return redirect(url_for("dashboard"))
    with SessionLocal() as db:
        profile = db.execute(select(CompanyProfile).where(CompanyProfile.user_id == current_user.id)).scalar_one_or_none()
        if not profile:
            flash("Please submit company registration first.", "warning")
            return redirect(url_for("company_register"))
        if not profile.approved:
            flash("Your company is pending approval.", "info")
            return redirect(url_for("dashboard"))

        if request.method == "POST":

            # create
            name = request.form.get("name","").strip()
            formula = request.form.get("formula","").strip()
            approved_date = request.form.get("approved_date","").strip()
            batch_no = request.form.get("batch_no","").strip()
            qr_file = request.files.get("qr_image")
            qr_filename = save_upload(qr_file)
            adate = None
            if approved_date:
                try: adate = datetime.strptime(approved_date, "%Y-%m-%d").date()
                except: adate = None
            med = Medicine(company_id=profile.id, name=name, formula=formula, approved_date=adate,
                           batch_no=batch_no, qr_image=qr_filename)
            try:
                db.add(med); db.commit()
                flash("Medicine added.", "success")
            except Exception:
                db.rollback(); flash("Batch number must be unique.", "danger")

        meds = db.query(Medicine).filter(Medicine.company_id == profile.id).order_by(Medicine.created_at.desc()).all()
        return render_template("company_medicines.html", meds=meds)

@app.route("/company/medicines/<int:mid>/edit", methods=["GET","POST"])
@login_required
def company_edit_medicine(mid):
    if current_user.role != ROLE_COMPANY:
        return jsonify({"ok": False}), 403
    with SessionLocal() as db:
        profile = db.execute(select(CompanyProfile).where(CompanyProfile.user_id == current_user.id)).scalar_one_or_none()
        med = db.get(Medicine, mid)
        if not med or med.company_id != (profile.id if profile else None):
            flash("Not found.", "danger"); return redirect(url_for("company_medicines"))
        if request.method == "POST":

            med.name = request.form.get("name", med.name)
            med.formula = request.form.get("formula", med.formula)
            approved_date = request.form.get("approved_date","").strip()
            if approved_date:
                try: med.approved_date = datetime.strptime(approved_date, "%Y-%m-%d").date()
                except: pass
            new_batch = request.form.get("batch_no", med.batch_no).strip()
            med.batch_no = new_batch or med.batch_no
            qr_file = request.files.get("qr_image")
            if qr_file and qr_file.filename:
                fname = save_upload(qr_file)
                if fname: med.qr_image = fname
            try:
                db.commit()
                app.logger.info(f"Action company_edit_medicine by user {current_user.id}")
                flash("Updated.", "success")
            except Exception:
                db.rollback()
                flash("Batch number must be unique.", "danger")
            return redirect(url_for("company_medicines"))
        return render_template("company_edit_medicine.html", med=med)

@app.post("/company/medicines/<int:mid>/delete")
@login_required
def company_delete_medicine(mid):
    if current_user.role != ROLE_COMPANY:
        return jsonify({"ok": False}), 403
    with SessionLocal() as db:
        profile = db.execute(select(CompanyProfile).where(CompanyProfile.user_id == current_user.id)).scalar_one_or_none()
        med = db.get(Medicine, mid)
        if not med or not profile or med.company_id != profile.id:
            return jsonify({"ok": False}), 404
        db.delete(med); db.commit()
    return redirect(url_for("company_medicines"))

# Admin view medicines
@app.get("/admin/medicines")
@login_required
def admin_medicines():
    if current_user.role != ROLE_ADMIN:
        flash("Admin only.", "danger")
        return redirect(url_for("dashboard"))
    with SessionLocal() as db:
        meds = db.query(Medicine).order_by(Medicine.created_at.desc()).all()
    return render_template("admin_medicines.html", meds=meds)

@app.post("/admin/medicines/<int:mid>/delete")
@login_required
def admin_delete_medicine(mid):
    if current_user.role != ROLE_ADMIN:
        return jsonify({"ok": False}), 403
    with SessionLocal() as db:
        med = db.get(Medicine, mid)
        if not med:
            return jsonify({"ok": False}), 404
        db.delete(med); db.commit()
    return redirect(url_for("admin_medicines"))

# Verification
@limiter.limit("30 per minute")
@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    msg = None

    if request.method == "POST":

        # --- analytics: log verify attempt ---
        with SessionLocal() as s2:
            from sqlalchemy import select
            comp = None
            company_name = request.form.get("company_name","")
            if company_name:
                comp = s2.execute(select(CompanyProfile).where(CompanyProfile.name.ilike(company_name))).scalars().first()
            comp_id = comp.id if comp else None
            term = company_name or request.form.get("cert_no","") or request.form.get("batch_no","") or "verify"
            s2.add(SearchLog(company_id=comp_id, term=term))
            s2.commit()
        mode = request.form.get("mode", "batch")
        if mode == "batch":
            batch_no = request.form.get("batch_no", "").strip()
            with SessionLocal() as db:
                med = db.execute(
                    select(Medicine).where(Medicine.batch_no == batch_no)
                ).scalar_one_or_none()
                if med:
                    result = med
                    with SessionLocal() as db2:
                        try:
                            db2.add(
                                VerificationLog(
                                    medicine_id=med.id,
                                    company_id=med.company_id,
                                    batch_no=med.batch_no,
                                    ip=request.remote_addr,
                                    user_agent=str(request.user_agent),
                                )
                            )
                            db2.commit()
                        except Exception as e:
                            app.logger.warning(f"Verify log failed: {e}")
                else:
                    msg = "No record found for this batch number."

        elif mode == "qr":
            img = request.files.get("qr_image")
            fname = save_upload(img)
            if not fname:
                msg = "Please upload an image."
            else:
                data, err = decode_qr_image(UPLOAD_DIR / fname)
                if err:
                    msg = f"QR decode failed: {err}"
                else:
                    with SessionLocal() as db:
                        med = db.execute(
                            select(Medicine).where(Medicine.batch_no == data)
                        ).scalar_one_or_none()
                        if med:
                            result = med
                            with SessionLocal() as db2:
                                try:
                                    db2.add(
                                        VerificationLog(
                                            medicine_id=med.id,
                                            company_id=med.company_id,
                                            batch_no=med.batch_no,
                                            ip=request.remote_addr,
                                            user_agent=str(request.user_agent),
                                        )
                                    )
                                    db2.commit()
                                except Exception as e:
                                    app.logger.warning(f"Verify log failed: {e}")
                        else:
                            msg = "QR decoded, but no matching medicine found."

    recall_info = None
    if result:
        with SessionLocal() as db:
            rec = db.execute(
                select(Recall).where(Recall.medicine_id == result.id)
            ).scalar_one_or_none()
            if rec:
                recall_info = {"recalled": True, "reason": rec.reason}

    return render_template(
        "verify.html", result=result, msg=msg, recall_info=recall_info
    )

@app.get("/api/verify")
@limiter.limit("60 per minute")
def api_verify():
    batch = request.args.get("batch", "").strip()
    if not batch:
        return jsonify({"ok": False, "error": "batch required"}), 400
    with SessionLocal() as db:
        med = db.execute(
            select(Medicine).where(Medicine.batch_no == batch)
        ).scalar_one_or_none()
        if not med:
            return jsonify({"ok": True, "status": "not_found"})
        # check recall
        recall = db.execute(
            select(Recall).where(Recall.medicine_id == med.id)
        ).scalar_one_or_none()
        recall_data = {"recalled": bool(recall), "reason": getattr(recall, "reason", None)}
        data = {
            "ok": True,
            "status": "valid",
            "medicine": {
                "id": med.id,
                "name": med.name,
                "formula": med.formula,
                "batch_no": med.batch_no,
                "approved_date": med.approved_date.isoformat() if med.approved_date else None,
                "expiry_date": med.expiry_date.isoformat() if med.expiry_date else None,
                "company_id": med.company_id,
            },
            "recall": recall_data,
        }
        # log BEFORE returning
        try:
            db.add(VerificationLog(
                medicine_id=med.id,
                company_id=med.company_id,
                batch_no=med.batch_no,
                ip=request.remote_addr,
                user_agent=str(request.user_agent)
            ))
            db.commit()
        except Exception as e:
            app.logger.warning(f'API verify log failed: {e}')
        return jsonify(data)

@app.get("/verify/live")
def verify_live():
    # Front-end live QR scan (html5-qrcode). On success it redirects to /verify with batch prefilled.
    return render_template("verify_live.html")

# Health & uploads
@app.get("/health")
def health():
    return jsonify({"status":"ok"})

@app.get("/uploads/<path:name>")
def uploads(name):
    return send_from_directory(UPLOAD_DIR, name)

@app.get("/search")
def search():
    q = (request.args.get("q") or "").strip()
    batch_no = (request.args.get("batch") or "").strip()
    company = (request.args.get("company") or "").strip()
    with SessionLocal() as db:
        query = db.query(Medicine).join(CompanyProfile, Medicine.company_id == CompanyProfile.id)
        if q:
            like = f"%{q}%"
            query = query.filter((Medicine.name.ilike(like)) | (Medicine.formula.ilike(like)))
        if batch_no:
            query = query.filter(Medicine.batch_no.ilike(f"%{batch_no}%"))
        if company:
            query = query.filter(CompanyProfile.company_name.ilike(f"%{company}%"))
        results = query.order_by(Medicine.created_at.desc()).all()
    return render_template("search.html", results=results, q=q, batch_no=batch_no, company=company)

@app.post('/admin/medicines/<int:mid>/recall')
@login_required
def admin_recall_medicine(mid):
    if current_user.role != ROLE_ADMIN:
        return jsonify({'ok': False}), 403
    reason = request.form.get('reason','')
    with SessionLocal() as db:
        med = db.get(Medicine, mid)
        if not med: return jsonify({'ok': False}), 404
        existing = db.execute(select(Recall).where(Recall.medicine_id==mid)).scalar_one_or_none()
        if existing:
            existing.reason = reason
        else:
            db.add(Recall(medicine_id=mid, reason=reason))
        db.commit()
    flash('Medicine marked as recalled.', 'success')
    return redirect(url_for('admin_medicines'))




@app.route('/admin/medicines/<int:mid>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_medicine(mid):
    if current_user.role != ROLE_ADMIN:
        return redirect(url_for('dashboard'))
    with SessionLocal() as db:
        med = db.get(Medicine, mid)
        if not med:
            flash('Medicine not found', 'danger')
            return redirect(url_for('admin_medicines'))
        if request.method == 'POST':
            med.name = request.form.get('name', med.name)
            med.formula = request.form.get('formula', med.formula)
            med.batch_no = request.form.get('batch_no', med.batch_no)
            ad = request.form.get('approved_date', '').strip()
            ed = request.form.get('expiry_date', '').strip()
            if ad:
                try:
                    med.approved_date = datetime.strptime(ad, '%Y-%m-%d').date()
                except Exception:
                    pass
            if ed:
                try:
                    med.expiry_date = datetime.strptime(ed, '%Y-%m-%d').date()
                except Exception:
                    pass
            company_id = request.form.get('company_id')
            if company_id:
                try:
                    med.company_id = int(company_id)
                except Exception:
                    pass
            qr_file = request.files.get('qr_image')
            if qr_file:
                qr_filename = save_upload(qr_file)
                if qr_filename:
                    med.qr_image = qr_filename
            db.commit()
            flash('Medicine updated successfully', 'success')
            return redirect(url_for('admin_medicines'))
        companies = db.query(CompanyProfile).all()
        return render_template('admin_edit_medicine.html', medicine=med, companies=companies)@app.post('/admin/medicines/<int:mid>/recall/remove')
@login_required
def admin_unrecall_medicine(mid):
    if current_user.role != ROLE_ADMIN:
        return jsonify({'ok': False}), 403
    with SessionLocal() as db:
        rec = db.execute(select(Recall).where(Recall.medicine_id==mid)).scalar_one_or_none()
        if rec: db.delete(rec); db.commit()
    flash('Recall removed.', 'success')
    return redirect(url_for('admin_medicines'))

@app.get('/admin/stats')
@login_required
def admin_stats():
    if current_user.role != ROLE_ADMIN:
        return redirect(url_for('dashboard'))
    with SessionLocal() as db:
        total_companies = db.query(CompanyProfile).count()
        approved_companies = db.query(CompanyProfile).where(CompanyProfile.approved==True).count()
        total_medicines = db.query(Medicine).count()
        # expiring soon (30,60,90 days)
        today = datetime.utcnow().date()
        expiring_30 = db.query(Medicine).where(Medicine.expiry_date != None).where(Medicine.expiry_date <= today + timedelta(days=30)).count()
        expiring_60 = db.query(Medicine).where(Medicine.expiry_date != None).where(Medicine.expiry_date <= today + timedelta(days=60)).count()
        expiring_90 = db.query(Medicine).where(Medicine.expiry_date != None).where(Medicine.expiry_date <= today + timedelta(days=90)).count()
        # top company by verifications
        from sqlalchemy import func
        rows = db.execute(select(VerificationLog.company_id, func.count().label('cnt')).group_by(VerificationLog.company_id).order_by(func.count().desc())).all()
        top_company = None; top_count = 0
        if rows and rows[0][0]:
            top_company = db.get(CompanyProfile, rows[0][0]); top_count = rows[0][1]
        per_company = db.execute(select(CompanyProfile.id, CompanyProfile.company_name, func.count(Medicine.id)).join(Medicine, Medicine.company_id==CompanyProfile.id, isouter=True).group_by(CompanyProfile.id)).all()
    return render_template('dashboard.html', admin_stats={'total_companies': total_companies, 'approved_companies': approved_companies, 'total_medicines': total_medicines, 'expiring': {'30': expiring_30, '60': expiring_60, '90': expiring_90}, 'top_company': {'name': getattr(top_company, 'company_name', None), 'count': top_count}, 'per_company': per_company})

@app.get('/admin/medicines/new')
@login_required
def admin_new_medicine():
    if current_user.role != ROLE_ADMIN:
        return redirect(url_for('dashboard'))
    with SessionLocal() as db:
        companies = db.query(CompanyProfile).where(CompanyProfile.approved==True).all()
    return render_template('admin_medicines.html', new_mode=True, companies=companies)

@app.post('/admin/medicines/new')
@login_required
def admin_create_medicine():
    if current_user.role != ROLE_ADMIN:
        return redirect(url_for('dashboard'))
    name = request.form.get('name','').strip()
    formula = request.form.get('formula','').strip()
    batch_no = request.form.get('batch_no','').strip()
    approved_date = request.form.get('approved_date','').strip()
    expiry_date = request.form.get('expiry_date','').strip()
    company_id = int(request.form.get('company_id','0') or 0)
    qr_image = request.files.get('qr_image')
    qr_filename = save_upload(qr_image)
    ad = datetime.strptime(approved_date, '%Y-%m-%d').date() if approved_date else None
    ed = datetime.strptime(expiry_date, '%Y-%m-%d').date() if expiry_date else None
    with SessionLocal() as db:
        m = Medicine(company_id=company_id, name=name, formula=formula, batch_no=batch_no, approved_date=ad, expiry_date=ed, qr_image=qr_filename)
        db.add(m); db.commit()
    flash('Medicine added.', 'success')
    return redirect(url_for('admin_medicines'))

# ---- Run app at the very end (so all routes above register) ----


@app.route("/admin/reports")
@login_required
def admin_reports():
    if not current_user.is_admin:
        return redirect(url_for("dashboard"))
    from sqlalchemy import func, select
    with SessionLocal() as s:
        total_companies = s.scalar(select(func.count()).select_from(CompanyProfile))
        approved_companies = s.scalar(select(func.count()).select_from(CompanyProfile).where(CompanyProfile.approved == True))
        pending_companies = total_companies - approved_companies

        # Most searched companies (top 10)
        rows = s.execute(
            select(CompanyProfile.name, func.count(SearchLog.id).label("cnt"))
            .join(SearchLog, SearchLog.company_id == CompanyProfile.id, isouter=True)
            .group_by(CompanyProfile.id)
            .order_by(func.count(SearchLog.id).desc())
            .limit(10)
        ).all()
        top_companies = [{"name": r[0], "count": int(r[1] or 0)} for r in rows]

    return render_template("admin_reports.html",
                           total_companies=total_companies,
                           approved_companies=approved_companies,
                           pending_companies=pending_companies,
                           top_companies=top_companies)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)



