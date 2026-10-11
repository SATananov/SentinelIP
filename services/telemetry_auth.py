import hashlib
import hmac
import secrets


TOKEN_ITERATIONS = 200_000


def generate_sensor_token() -> str:
    return secrets.token_urlsafe(32)


def hash_sensor_token(token: str, salt: bytes, iterations: int = TOKEN_ITERATIONS) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, iterations)
    return digest.hex()


def verify_sensor_token(token: str, salt: bytes, token_hash: str, iterations: int) -> bool:
    candidate = hash_sensor_token(token, salt, iterations)
    return hmac.compare_digest(candidate, token_hash)