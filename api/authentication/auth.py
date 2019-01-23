import jwt
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify

SECRET_KEY = "fdfdwdcvb"

def generate_token(admin = False):
    try:
        # set up a payload with an expiration time
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=60),
            'iat': datetime.utcnow(),
            'sub': admin
        }
        # create the byte string token using the payload and the SECRET key
        jwt_string = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode("utf-8")
        return jwt_string

    except Exception as e:
        # return an error in string format if an exception occurs
        return str(e)


@staticmethod
def decode_token(token):
    """Decodes the access token from the Authorization header."""
    try:
        # try to decode the token using our SECRET variable
        payload = jwt.decode(token, SECRET_KEY))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        # the token is expired, return an error string
        return "Expired token. Please login to get a new token"
    except jwt.InvalidTokenError:
        # the token is invalid, return an error string
        return "Invalid token. Please register or login"

def extract_token_from_header():
    """Get token fromm the headers"""
    authorization_header = request.headers.get("Authorization")
    if not authorization_header or "Bearer" not in authorization_header:
        return jsonify({
            "error": "Bad authorization header",
            "status": 400
        })
    token = authorization_header.split(" ")[1]
    return token

    







