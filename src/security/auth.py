import os
import jwt
import datetime
from typing import Optional, Dict

JWT_SECRET = os.getenv("SRS_JWT_SECRET", "dev-only-secret-change-me")
JWT_ALG = "HS256"
JWT_EXP_MIN = int(os.getenv("SRS_JWT_EXP_MIN", "30"))

def generate_token(user_id: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {"sub": user_id, "iat": now, "exp": now + datetime.timedelta(minutes=JWT_EXP_MIN)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(token: str) -> Optional[Dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
