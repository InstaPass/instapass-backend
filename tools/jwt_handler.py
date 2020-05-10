import jwt
from main import db
from models.models import *
import time


secret_key = open('config/secret.txt').read()


def ts(offset: int = 0):
    return int(time.time() + offset)


def user_id_encode(user_id: int):
    # user = User.query.filter_by(id=user_id).first()
    return str(jwt.encode({'id': user_id, 'exp': ts(86400)}, secret_key, algorithm='HS256'), encoding='utf-8')


def user_id_decode(jwt_str: str):
    try:
        return jwt.decode(bytes(jwt_str, encoding='utf-8'), secret_key, algorithm='HS256')
    except jwt.exceptions.DecodeError:
        return {}
