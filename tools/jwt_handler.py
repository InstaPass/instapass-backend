import jwt
import time


secret_key = open('config/secret.txt').read()


def ts(offset: int = 0):
    return int(time.time() + offset)


def user_id_encode(user_id: int):
    # user = User.query.filter_by(id=user_id).first()
    return str(jwt.encode({'id': user_id, 'exp': ts(86400)}, secret_key, algorithm='HS256'), encoding='utf-8')


def decode(jwt_str: str):
    try:
        return jwt.decode(bytes(jwt_str, encoding='utf-8'), secret_key, algorithm='HS256')
    except jwt.exceptions.DecodeError:
        return {}


def access_qrcode_encode(user_id: int, community: int):
    return str(jwt.encode({'type': 'access', 'id': user_id, 'community_id': community, 'exp': ts(60)}, secret_key,
                          algorithm='HS256'), encoding='utf-8')


def create_qrcode_encode(community: int, temp: bool, reason: str):
    return str(jwt.encode({'type': 'create', 'community_id': community, 'temp': temp, 'exp': ts(60), 'reason': reason},
                          secret_key, algorithm='HS256'), encoding='utf-8')
