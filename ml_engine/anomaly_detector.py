import os
import joblib
import numpy as np

from sklearn.ensemble import IsolationForest


class AnomalyDetector:

    def __init__(self, model_dir="models"):

        self.model_dir = model_dir

        os.makedirs(
            self.model_dir,
            exist_ok=True
        )

        self.model_path = os.path.join(
            self.model_dir,
            "isolation_forest.pkl"
        )

        if os.path.exists(self.model_path):

            self.model = joblib.load(
                self.model_path
            )

        else:

            self.model = IsolationForest(
                contamination=0.08,
                random_state=42
            )

            training_data = np.array([

                [9, 0, 1, 1, 1, 1, 5, 600, 0],
                [10, 1, 1, 1, 1, 1, 8, 700, 0],
                [13, 2, 1, 1, 1, 1, 12, 650, 1],
                [15, 3, 1, 1, 1, 1, 20, 720, 0],
                [17, 4, 1, 1, 1, 1, 30, 800, 0],
                [11, 5, 1, 1, 1, 1, 18, 610, 0],
                [14, 6, 1, 1, 1, 1, 25, 690, 0]

            ])

            self.model.fit(training_data)

            joblib.dump(
                self.model,
                self.model_path
            )

    def score(self, user_id, features):

        features = np.array(
            features
        ).reshape(1, -1)

        prediction = self.model.predict(features)[0]

        anomaly_score = float(
            self.model.decision_function(features)[0]
        )

        risk_score = int(
            (1 - max(min(anomaly_score, 1), -1)) * 50
        )

        reasons = []

        if features[0][2] == 0:
            reasons.append("New IP Address")

        if features[0][3] == 0:
            reasons.append("New Login Location")

        if features[0][4] == 0:
            reasons.append("New Device")

        if features[0][5] == 0:
            reasons.append("New Browser")

        if features[0][0] < 6 or features[0][0] > 22:
            reasons.append("Unusual Login Time")

        if prediction == -1:

            if risk_score >= 70:
                risk = "high"
                response = "Alert Generated"

            else:
                risk = "medium"
                response = "Access Granted with Monitoring"

        else:

            risk = "low"
            response = "Access Granted"

        return {

            "anomaly_score": anomaly_score,

            "risk_score": risk_score,

            "risk_level": risk,

            "anomaly_type": "Behavioural Login Analysis",

            "system_response": response,

            "explanation": (
                ", ".join(reasons)
                if reasons
                else "Normal login behaviour"
            )

        }

    def retrain_all(self, db_session):

        from database import LoginActivity
        from ml_engine.feature_extractor import (
            extract_login_features
        )

        successful_logins = (
            LoginActivity.query
            .filter_by(
                login_status="success"
            )
            .all()
        )

        if len(successful_logins) < 20:
            return 0

        training_data = []

        for login in successful_logins:

            features = extract_login_features(
                login.user_id,
                login,
                db_session
            )

            training_data.append(features)

        training_data = np.array(
            training_data
        )

        self.model = IsolationForest(
            contamination=0.08,
            random_state=42
        )

        self.model.fit(
            training_data
        )

        joblib.dump(
            self.model,
            self.model_path
        )

        return len(training_data)