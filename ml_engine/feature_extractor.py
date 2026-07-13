from datetime import datetime

from database import LoginActivity


def extract_login_features(user_id, current_login, db_session):
    """
    Extracts the 9 behavioural features used by the
    Isolation Forest model.
    """

    previous_logins = (
        LoginActivity.query
        .filter(
            LoginActivity.user_id == user_id,
            LoginActivity.login_status == "success",
            LoginActivity.id != current_login.id
        )
        .all()
    )

    login_hour = current_login.login_time.hour

    weekday = current_login.login_time.weekday()

    known_ips = {
        login.ip_address
        for login in previous_logins
    }

    known_locations = {
        login.login_location
        for login in previous_logins
    }

    known_devices = {
        login.device_type
        for login in previous_logins
    }

    known_browsers = {
        login.browser_type
        for login in previous_logins
    }

    ip_known = (
        1 if current_login.ip_address in known_ips
        else 0
    )

    location_known = (
        1 if current_login.login_location in known_locations
        else 0
    )

    device_known = (
        1 if current_login.device_type in known_devices
        else 0
    )

    browser_known = (
        1 if current_login.browser_type in known_browsers
        else 0
    )

    previous_count = len(previous_logins)

    average_session = 600

    if previous_logins:

        durations = [
            login.session_duration
            for login in previous_logins
            if login.session_duration
        ]

        if durations:
            average_session = int(
                sum(durations) / len(durations)
            )

    failed_attempts = (
        LoginActivity.query
        .filter_by(
            user_id=user_id,
            login_status="failed"
        )
        .count()
    )

    return [

        login_hour,

        weekday,

        ip_known,

        location_known,

        device_known,

        browser_known,

        previous_count,

        average_session,

        failed_attempts

    ]