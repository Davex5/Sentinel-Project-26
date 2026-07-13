import os
from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session
)

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from database import (
    db,
    User,
    LoginActivity,
    AnomalyReport,
    Alert,
    MLModelMeta
)

from ml_engine.anomaly_detector import AnomalyDetector
from ml_engine.feature_extractor import extract_login_features

from utils.request_meta import (
    get_client_ip,
    parse_user_agent,
    mock_geolocation
)

from utils.validators import (
    is_valid_email,
    is_valid_username,
    password_strength
)


def utcnow():
    """Naive UTC timestamp, without the deprecated datetime.utcnow() call."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# In production, set a real SECRET_KEY via an environment variable instead
# of relying on the fallback below.
app.config["SECRET_KEY"] = os.environ.get(
    "SENTINEL_SECRET_KEY", "sentinel-secret-key-dev-only"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{os.path.join(BASE_DIR, 'data', 'anomaly_system.db')}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

detector = AnomalyDetector(
    model_dir=os.path.join(BASE_DIR, "ml_engine", "saved_models")
)


@login_manager.user_loader
def load_user(user_id):
    # db.session.get() replaces the deprecated Query.get()
    return db.session.get(User, int(user_id))


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # .get() instead of request.form["x"] so a missing field returns
        # "" instead of raising a 400 KeyError before we get to validate it
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []

        if not full_name:
            errors.append("Full name is required.")

        if not is_valid_email(email):
            errors.append("Please enter a valid email address.")

        if not is_valid_username(username):
            errors.append(
                "Username must be 3-30 characters "
                "(letters, numbers, underscore only)."
            )

        strength = password_strength(password)

        if not strength["is_strong_enough"]:
            errors.append(
                "Password needs " + ", ".join(strength["missing"]) + "."
            )

        if password != confirm_password:
            errors.append("Passwords do not match.")

        if not errors:
            existing_user = User.query.filter(
                (User.email == email) |
                (User.username == username)
            ).first()

            if existing_user:
                errors.append("Email or username already exists.")

        if errors:
            for error in errors:
                flash(error, "error")

            return render_template(
                "register.html",
                full_name=full_name,
                email=email,
                username=username
            )

        user = User(
            full_name=full_name,
            email=email,
            username=username,
            password_hash=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(
            username=username
        ).first()

        ip = get_client_ip(request)

        device, browser = parse_user_agent(
            request.headers.get("User-Agent")
        )

        location = mock_geolocation(ip)

        # Failed Login
        if (
            not user or
            not check_password_hash(
                user.password_hash,
                password
            )
        ):

            failed = LoginActivity(
                user_id=user.id if user else None,
                username_attempted=username,
                login_time=utcnow(),
                ip_address=ip,
                device_type=device,
                browser_type=browser,
                login_location=location,
                login_status="failed"
            )

            db.session.add(failed)
            db.session.commit()

            flash(
                "Invalid username or password.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # Successful Login
        activity = LoginActivity(
            user_id=user.id,
            username_attempted=username,
            login_time=utcnow(),
            ip_address=ip,
            device_type=device,
            browser_type=browser,
            login_location=location,
            login_status="success"
        )

        db.session.add(activity)
        db.session.commit()

        features = extract_login_features(
            user.id,
            activity,
            db.session
        )

        result = detector.score(
            user.id,
            features
        )

        report = AnomalyReport(
            login_id=activity.id,
            anomaly_score=result["anomaly_score"],
            risk_score=result["risk_score"],
            anomaly_type=result["anomaly_type"],
            risk_level=result["risk_level"],
            detection_time=utcnow(),
            system_response=result["system_response"]
        )

        db.session.add(report)
        db.session.commit()

        if result["risk_level"] in ["medium", "high"]:

            alert = Alert(
                anomaly_id=report.id,
                alert_message=result["explanation"],
                alert_status="open"
            )

            db.session.add(alert)
            db.session.commit()

        successful = LoginActivity.query.filter_by(
            login_status="success"
        ).count()

        if successful >= 20 and successful % 20 == 0:
            detector.retrain_all(
                db.session
            )

        login_user(user)

        session["last_anomaly"] = result

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


@app.route("/dashboard")
@login_required
def dashboard():

    activities = (
        LoginActivity.query
        .filter_by(user_id=current_user.id)
        .order_by(LoginActivity.login_time.desc())
        .all()
    )

    return render_template(
        "dashboard.html",
        activities=activities,
        last_anomaly=session.get("last_anomaly")
    )


@app.route("/admin")
@login_required
def admin_dashboard():

    total_logins = LoginActivity.query.count()

    failed_logins = (
        LoginActivity.query
        .filter_by(login_status="failed")
        .count()
    )

    successful_logins = (
        LoginActivity.query
        .filter_by(login_status="success")
        .count()
    )

    risk_counts = {
        "low": AnomalyReport.query.filter_by(
            risk_level="low"
        ).count(),

        "medium": AnomalyReport.query.filter_by(
            risk_level="medium"
        ).count(),

        "high": AnomalyReport.query.filter_by(
            risk_level="high"
        ).count()
    }

    alerts = (
        Alert.query
        .order_by(Alert.id.desc())
        .all()
    )

    recent_logins = (
        LoginActivity.query
        .order_by(LoginActivity.login_time.desc())
        .limit(20)
        .all()
    )

    return render_template(
        "admin.html",
        total_logins=total_logins,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        risk_counts=risk_counts,
        alerts=alerts,
        recent_logins=recent_logins
    )


@app.route("/resolve-alert/<int:alert_id>", methods=["POST"])
@login_required
def resolve_alert(alert_id):

    alert = db.session.get(Alert, alert_id)

    if alert is None:
        flash("Alert not found.", "error")
        return redirect(url_for("admin_dashboard"))

    alert.alert_status = "resolved"

    alert.admin_response = request.form.get(
        "response",
        "Reviewed by Administrator"
    )

    alert.response_time = utcnow()

    db.session.commit()

    flash(
        "Alert resolved successfully.",
        "success"
    )

    return redirect(
        url_for("admin_dashboard")
    )


@app.route("/api/dashboard-stats")
@login_required
def api_dashboard_stats():

    return jsonify({

        "total_logins": LoginActivity.query.count(),

        "successful_logins": LoginActivity.query.filter_by(
            login_status="success"
        ).count(),

        "failed_logins": LoginActivity.query.filter_by(
            login_status="failed"
        ).count(),

        "low": AnomalyReport.query.filter_by(
            risk_level="low"
        ).count(),

        "medium": AnomalyReport.query.filter_by(
            risk_level="medium"
        ).count(),

        "high": AnomalyReport.query.filter_by(
            risk_level="high"
        ).count()

    })


@app.route("/api/login-activity/<int:user_id>")
@login_required
def api_login_activity(user_id):

    rows = (
        LoginActivity.query
        .filter_by(user_id=user_id)
        .order_by(LoginActivity.login_time.desc())
        .all()
    )

    return jsonify(
        [row.to_dict() for row in rows]
    )


@app.route("/api/retrain", methods=["POST"])
@login_required
def api_retrain():

    trained_records = detector.retrain_all(
        db.session
    )

    meta = MLModelMeta(
        algorithm_name="Isolation Forest",
        training_accuracy=None,
        training_date=utcnow(),
        dataset_version=f"trained={trained_records}",
        model_status="active"
    )

    db.session.add(meta)
    db.session.commit()

    flash(
        f"Model retrained using {trained_records} successful login records.",
        "success"
    )

    return redirect(
        url_for("admin_dashboard")
    )


@app.route("/logout")
@login_required
def logout():

    logout_user()

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login")
    )


def init_db():

    os.makedirs(
        os.path.join(BASE_DIR, "data"),
        exist_ok=True
    )

    with app.app_context():
        db.create_all()


# Runs both when this file is executed directly (python app.py) and when
# it's imported by a WSGI server such as gunicorn (gunicorn app:app),
# which is how platforms like Render run the app in production.
init_db()

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )