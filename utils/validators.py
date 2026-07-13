"""
Server-side input validation for registration.

Client-side checks (HTML attributes, JS strength meter) are a UX
convenience only — they can be bypassed, so every rule here is
re-checked on the server before a user is created.
"""

import re

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def is_valid_email(email):
    """Basic structural check: something@something.tld, no whitespace."""
    return bool(email) and bool(EMAIL_PATTERN.match(email.strip()))


def is_valid_username(username):
    """3-30 characters, letters/numbers/underscore only."""
    return bool(username) and bool(USERNAME_PATTERN.match(username.strip()))


def password_strength(password):
    """
    Score a password from 0-4 and report which rules it fails.

    Rules checked:
      - at least 8 characters
      - at least one uppercase letter
      - at least one lowercase letter
      - at least one digit
      - at least one special character
    """
    password = password or ""

    checks = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    score = sum(checks.values())

    missing = []

    if not checks["length"]:
        missing.append("at least 8 characters")
    if not checks["uppercase"]:
        missing.append("an uppercase letter")
    if not checks["lowercase"]:
        missing.append("a lowercase letter")
    if not checks["digit"]:
        missing.append("a number")
    if not checks["special"]:
        missing.append("a special character")

    return {
        "score": score,
        "checks": checks,
        "missing": missing,
        "is_strong_enough": checks["length"] and score >= 4,
    }