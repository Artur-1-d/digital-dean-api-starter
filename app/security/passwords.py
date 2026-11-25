
"""Fixed educational PBKDF2 password profile."""
import hashlib
import hmac
import re
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000
SALT_BYTES = 16
DERIVED_BYTES = 32
MIN_PASSWORD_CHARS = 15
MAX_PASSWORD_CHARS = 128
MAX_PASSWORD_BYTES = 512


def password_bytes(password: str, *, registration: bool = False) -> bytes:
    if not isinstance(password, str):
        raise ValueError("password must be text")

    minimum = MIN_PASSWORD_CHARS if registration else 1

    if not minimum <= len(password) <= MAX_PASSWORD_CHARS:
        raise ValueError("password length or characters invalid")

    if "\x00" in password:
        raise ValueError("password length or characters invalid")

    try:
        raw = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("password encoding invalid") from exc

    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("password byte length invalid")

    return raw


def make_password_record(password: str) -> tuple[str, str]:
    raw = password_bytes(password, registration=True)
    salt = secrets.token_bytes(SALT_BYTES)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        raw,
        salt,
        ITERATIONS,
        dklen=DERIVED_BYTES,
    )

    record = f"{ALGORITHM}${ITERATIONS}${derived.hex()}"

    return record, salt.hex()


def verify_password(password: str, record: str, salt_hex: str) -> bool:
    try:
        raw = password_bytes(password)

        if not isinstance(record, str):
            return False

        if not isinstance(salt_hex, str):
            return False

        if re.fullmatch(r"[0-9a-f]{32}", salt_hex) is None:
            return False

        match = re.fullmatch(
            r"pbkdf2_sha256\$600000\$([0-9a-f]{64})",
            record,
        )

        if match is None:
            return False

        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(match.group(1))

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            raw,
            salt,
            ITERATIONS,
            dklen=DERIVED_BYTES,
        )

        return hmac.compare_digest(derived, expected)

    except (ValueError, TypeError):
        return False
