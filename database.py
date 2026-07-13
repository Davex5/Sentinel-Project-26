from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    account_status = db.Column(
        db.String(20),
        default="active"
    )

    registration_date = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    login_activities = db.relationship(
        "LoginActivity",
        backref="user",
        lazy=True
    )


class LoginActivity(db.Model):
    __tablename__ = "login_activities"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    username_attempted = db.Column(db.String(80))

    login_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    ip_address = db.Column(db.String(45))
    device_type = db.Column(db.String(50))
    browser_type = db.Column(db.String(50))
    login_location = db.Column(db.String(120))

    login_status = db.Column(db.String(20))

    session_duration = db.Column(
        db.Integer,
        nullable=True
    )

    anomaly_report = db.relationship(
        "AnomalyReport",
        backref="login_activity",
        uselist=False,
        lazy=True
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username_attempted": self.username_attempted,
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "ip_address": self.ip_address,
            "device_type": self.device_type,
            "browser_type": self.browser_type,
            "login_location": self.login_location,
            "login_status": self.login_status
        }


class AnomalyReport(db.Model):
    __tablename__ = "anomaly_reports"

    id = db.Column(db.Integer, primary_key=True)

    login_id = db.Column(
        db.Integer,
        db.ForeignKey("login_activities.id"),
        nullable=False
    )

    anomaly_score = db.Column(db.Float)
    risk_score = db.Column(db.Integer)

    anomaly_type = db.Column(db.String(100))
    risk_level = db.Column(db.String(20))

    detection_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    system_response = db.Column(db.String(255))

    alerts = db.relationship(
        "Alert",
        backref="anomaly_report",
        lazy=True
    )


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    anomaly_id = db.Column(
        db.Integer,
        db.ForeignKey("anomaly_reports.id"),
        nullable=False
    )

    alert_message = db.Column(db.String(255))

    alert_status = db.Column(
        db.String(20),
        default="open"
    )

    admin_response = db.Column(
        db.String(255),
        nullable=True
    )

    response_time = db.Column(
        db.DateTime,
        nullable=True
    )


class MLModelMeta(db.Model):
    __tablename__ = "machine_learning_models"

    id = db.Column(db.Integer, primary_key=True)

    algorithm_name = db.Column(db.String(100))

    training_accuracy = db.Column(
        db.Float,
        nullable=True
    )

    training_date = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    dataset_version = db.Column(db.String(100))

    model_status = db.Column(
        db.String(20),
        default="active"
    )