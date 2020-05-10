from flask import *
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import config.dbinfo
import re
from jwt.exceptions import ExpiredSignatureError

app = Flask(__name__)
app.config.from_object(config.dbinfo)
db = SQLAlchemy(app)

from tools.jwt_handler import *
from models.models import *

db.create_all()


# finish init. Maybe do code refactor in the future.

# Tool methods


def params_not_given():
    return {"status": "err", "msg": "params not given"}, 400


def valid_login(username: str, password: str):
    user = User.query.filter_by(username=username).first()
    if not user or user.password != password:
        return False, ""
    return True, user_id_encode(user.id)


def valid_access(dweller: Dweller):
    return True


# Decorators


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
        except KeyError:
            return {"status": "error", "msg": "You're not login"}, 401
        if token == {}:
            return {"status": "error", "msg": "You're not login"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "Login expired"}, 401
        return f(*args, **kwargs)

    return decorated_function


def dweller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
            dweller = Dweller.query.filter_by(id=token['id']).first()
            if not dweller:
                return {"status": "error", "msg": "You're not a dweller"}, 400
        except KeyError:
            return {"status": "error", "msg": "You're not login"}, 401
        if token == {}:
            return {"status": "error", "msg": "You're not login"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "Login expired"}, 401
        g.dweller = dweller
        return f(*args, **kwargs)

    return decorated_function


def guard_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
            guard = Monitor.query.filter_by(id=token['id']).first()
            if not guard:
                return {"status": "error", "msg": "You're not a dweller"}, 400
        except KeyError:
            return {"status": "error", "msg": "You're not login"}, 401
        if token == {}:
            return {"status": "error", "msg": "You're not login"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "Login expired"}, 401
        g.guard = guard
        return f(*args, **kwargs)

    return decorated_function


# API Gateways


@app.route('/need_login_test')
@dweller_required
def need_login_test():
    return {"msg": "you're login"}


@app.route('/login', methods=['POST'])
def login():
    try:
        success, token = valid_login(request.json['username'], request.json['password'])
        if success:
            return {"jwt_token": token}
        else:
            return {"status": "err", "msg": "Wrong username or password"}, 401
    except KeyError:
        return params_not_given()


@app.route('/resident/qrcode', methods=['GET'])
@dweller_required
def get_qrcode():
    return {"status": "ok",
            "last_refresh_time": ts(),
            "secret": "instapass{%s}" % qrcode_encode(g.dweller.id, g.dweller.community_id)}


@app.route('/guard/validate', methods=['POST'])
@guard_required
def validate_qrcode():
    try:
        reason = request.json['reason']
        secret = request.json['secret']
        jwt_secret = re.match("instapass{(.*)}", secret).groups()[0]
        qr_json = decode(jwt_secret)
        if qr_json['community_id'] == g.guard.community_id:
            db.session.add(Log(community_id=qr_json['community_id'], user_id=qr_json['id'], temperature=37.0,
                               note=reason, access_time=ts()))
            dweller = Dweller.query.filter_by(id=qr_json['id']).first()
            dweller.last_access_time = ts()
            db.session.commit()
            return {"status": "ok", "validation": "accepted"}
        else:
            return {"status": "err", "msg": "permission denied"}, 403
    except KeyError:
        return params_not_given()
    except ExpiredSignatureError:
        return {"status": "err", "msg": "qrcode has expired"}, 400


@app.errorhandler(405)
def method_not_allowed(error):
    return {"msg": "method not allowed", "status": "err"}, 405


if __name__ == "__main__":
    app.run(host='0.0.0.0', port='8288')
