import binascii
import os
import re
from functools import wraps

import requests
from flask import *
from jwt.exceptions import ExpiredSignatureError
from sqlalchemy import and_

import config.dbinfo
from models.models import *
from tools.jwt_handler import *


app = Flask(__name__)


# finish init. Maybe do code refactor in the future.

# Tool methods

def get_communities(l):
    communities = []
    for elem in l:
        communities.append(elem.community_id)
    communities = db.session.query(Community).filter(Community.id.in_(communities)).all()
    retJSON = []
    for community in communities:
        retJSON.append({
            "community_id": community.id,
            "community": community.name,
            "address": community.address,
        })
    return retJSON


def is_role(user_id: int, role):
    user = role.query.filter_by(id=user_id).all()
    return user


def in_community(community_id: int, manage_list):
    for manage in manage_list:
        if community_id == manage.community_id:
            if isinstance(manage, Dweller) and manage.temp and not manage.inside:
                return None
            else:
                return manage

    return None


def params_not_given():
    return {"status": "err", "msg": "登录参数错误"}, 400


def valid_login(username: str, password: str):
    user = User.query.filter_by(username=username).first()
    if not user or user.password != password:
        return False, "", 0
    return True, user_id_encode(user.id), user.id


def valid_access(dweller: Dweller):
    return True


def valid_invitation(key: str):
    i = InviteKey.query.filter_by(key=key, used=False).first()
    if i:
        i.used = True
        db.session.commit()
        return i.community_id
    else:
        return -1


def get_invitation(id: int):
    r = str(binascii.hexlify(os.urandom(16)), encoding='utf-8')
    db.session.add(InviteKey(community_id=id, key=r, used=False))
    db.session.commit()
    return r


# Decorators


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
        except KeyError:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token == {}:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "会话过期"}, 401
        g.id = token['id']
        g.user = User.query.filter_by(id=g.id).first()
        return f(*args, **kwargs)

    return decorated_function


def dweller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
            dweller = is_role(token['id'], Dweller)
            if not dweller:
                return {"status": "error", "msg": "非居民账户"}, 403
        except KeyError:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token == {}:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "会话过期"}, 401
        g.dweller = dweller
        g.id = token['id']
        return f(*args, **kwargs)

    return decorated_function


def guard_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
            guard = is_role(token["id"], Monitor)
            if not guard:
                return {"status": "error", "msg": "非保安账户"}, 403
        except KeyError:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token == {}:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "会话过期"}, 401
        g.guard = guard
        g.id = token['id']
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = decode(request.headers['Jwt-Token'])
            admin = is_role(token["id"], Admin)
            if not admin:
                return {"status": "error", "msg": "非管理员账户"}, 403
        except KeyError:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token == {}:
            return {"status": "error", "msg": "尚未登录"}, 401
        if token['exp'] < ts():
            return {"status": "error", "msg": "会话过期"}, 401
        g.admin = admin
        g.id = token['id']
        return f(*args, **kwargs)

    return decorated_function


# API Gateways

@app.before_first_request
def create_db():
    db.create_all()


@app.after_request
def after(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Method'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'X-Requested-With,Content-Type,Jwt-Token'
    return resp


@app.route('/need_login_test')
@dweller_required
def need_login_test():
    return {"msg": "you're login"}


@app.route('/<role>/login', methods=['POST'])
def login(role):
    role_table = {"admin": Admin, "guard": Monitor, "resident": Dweller}
    try:
        if role != "resident":
            success, token, user_id = valid_login(
                request.json['username'], request.json['password'])
            if success:
                try:
                    if not is_role(user_id, role_table[role]):
                        return {"status": "error", "msg": f"非 {role} 角色"}, 403
                    else:
                        l = role_table[role].query.filter_by(id=user_id).all()
                        return {"status": "ok", "jwt_token": token, "working_communities": get_communities(l)}
                except KeyError:
                    return {"status": "err", "msg": f"无 {role} 角色"}, 403
            else:
                return {"status": "err", "msg": "无效凭据"}, 401
        else:
            u = User.query.filter_by(
                name=request.json["realname"], id_number=request.json["id_number"]).first()
            if u:
                return {"status": "ok", "jwt_token": user_id_encode(u.id)}
            else:
                return {"status": "err", "msg": "无此用户"}, 401
    except KeyError:
        return params_not_given()


@app.route('/resident/qrcode/<int:id>', methods=['GET'])
@dweller_required
def get_qrcode(id):
    if in_community(id, g.dweller):
        return {"status": "ok",
                "last_refresh_time": ts(),
                "secret": "instapass{%s}" % access_qrcode_encode(g.dweller[0].id, id)}
    else:
        return {"status": "error", "msg": "不属于此小区"}, 403


@app.route('/resident/community', methods=['GET'])
@login_required
def get_community_info():
    communities = []
    community_map = {}
    dweller = is_role(g.id, Dweller)
    if dweller:
        for d in dweller:
            community_map[d] = Community.query.filter_by(
                id=d.community_id).first()
    for c in community_map:
        communities.append({
            "community_id": community_map[c].id,
            "community": community_map[c].name,
            "address": community_map[c].address,
            "inside": c.inside,
            "temporary": c.temp,
            "strategy": "无限制"
        })
    return {"status": "ok", "communities": communities}


@app.route('/resident/community/enter', methods=['POST'])
@login_required
def enter_community():
    try:
        secret = request.json['secret']
        jwt_secret = re.match("instapass{(.*)}", secret).groups()[0]
        qr_json = decode(jwt_secret)
        if qr_json["type"] != "create":
            return {"status": "err", "msg": "无效 QR 码"}, 400
        community_id = qr_json["community_id"]
        temp = qr_json["temp"]
        dweller = Dweller.query.filter_by(
            id=g.id, community_id=community_id).first()
        if dweller:
            if dweller.temp and not dweller.inside:
                dweller.inside = True
            else:
                return {"status": "error", "msg": "已进入此小区"}, 400
            dweller.temp = temp
        else:
            dweller = Dweller(id=g.id, community_id=community_id,
                              last_access_time=0, inside=True, temp=temp)
            db.session.add(dweller)
        if dweller.temp:
            db.session.add(Log(community_id=dweller.community_id, user_id=dweller.id, temperature=37.0,
                               note=qr_json['reason'], access_time=ts(),
                               inside='inside' if dweller.inside else 'outside'))
        db.session.commit()
        community = Community.query.filter_by(id=community_id).first()
        return {"status": "ok", "temporary": temp, "community_id": community_id, "community": community.name}
    except KeyError:
        return params_not_given()
    except ExpiredSignatureError:
        return {"status": "err", "msg": "QR 码已过期"}, 400


@app.route('/resident/community/leave', methods=['POST'])
@dweller_required
def leave_community():
    try:
        community_id = request.json['community_id']
        if community_id == -1:
            return {"status": "error"}, 400
        else:
            db.session.delete(Dweller.query.filter_by(
                id=g.id, community_id=community_id).first())
            db.session.commit()
            return {"status": "ok"}
    except KeyError:
        return params_not_given()


@app.route('/resident/notifications', methods=['GET'])
@dweller_required
def resident_retrieve_notifications():
    is_all = request.args.get("all")
    user = User.query.filter_by(id=g.id).first()
    communities = []
    community_map = {}
    for dweller in g.dweller:
        if dweller.temp:
            continue
        communities.append(dweller.community_id)
        community_map[dweller.community_id] = Community.query.filter_by(
            id=dweller.community_id).first()
    last_retrieve_time = user.last_retrieve_time
    user.last_retrieve_time = ts()
    notifications = []
    if is_all is None:
        notices = db.session.query(Notice).filter(and_(
            Notice.create_time >= last_retrieve_time, Notice.community_id.in_(communities))).all()
    else:
        notices = db.session.query(Notice).filter(
            Notice.community_id.in_(communities)).all()
    for notice in notices:
        notifications.append({
            "community_id": notice.community_id,
            "community": community_map[notice.community_id].name,
            "address": community_map[notice.community_id].address,
            "content": notice.content,
            "author": notice.author,
            "release_time": notice.create_time
        })
    db.session.commit()
    return {"status": "ok", "last_retrieve_time": user.last_retrieve_time, "notifications": notifications}


@app.route('/resident/history/<int:id>', methods=['GET'])
@dweller_required
def get_history(id):
    dweller = in_community(id, g.dweller)
    community = Community.query.filter_by(id=id).first()
    logs = Log.query.filter_by(community_id=id, user_id=g.id).all()
    if not dweller:
        return {"status": "error"}, 403
    else:
        log_json = []
        for log in logs:
            log_json.append({
                "community_id": id,
                "community": community.name,
                "address": community.address,
                "time": log.access_time,
                "reason": log.note,
            })
        return {
            "status": "ok",
            "current_status": "inside" if dweller.inside else "outside",
            "last_exit_time": dweller.last_access_time,
            "history": log_json
        }


@app.route('/resident/info', methods=['GET', 'POST'])
@login_required
def get_info():
    if request.method == 'GET':
        return {
            "status": "ok",
            "variable_info": {
                "nickname": g.user.nickname,
                "phone_no": g.user.phone,
                "mail_address": g.user.email_address
            },
            "static_info": {
                "realname": g.user.name,
                "id_number": g.user.id_number
            }
        }
    else:
        try:
            g.user.nickname = request.json["variable_info"]["nickname"]
            g.user.phone = request.json["variable_info"]["phone_no"]
            g.user.email_address = request.json["variable_info"]["mail_address"]
            db.session.commit()
            return {"status": "ok"}
        except KeyError:
            return params_not_given()


@app.route('/resident/certificate', methods=['POST'])
def certificate():
    try:
        pic = request.json["id_card_snapshot"]
        match = re.match("data:image/.*;base64,(.*)", pic)
        if match:
            pic = match.groups()[0]
        resp = requests.post("https://shenfenzhe.market.alicloudapi.com/do", files={
            "image": (None, pic),
            "id_card_side": (None, "front")
        }, headers={
            'Authorization': 'APPCODE b6925f533db7458f8dd7c5a8d509d2ad'
        })
        id_number = resp.json()["msg"]["idcardno"]
        real_name = resp.json()["msg"]["name"]
        if not id_number or not real_name:
            return {"status": "error", "msg": "无效图片"}, 400
        u = User.query.filter_by(id_number=id_number, name=real_name).first()
        if not u:
            db.session.add(
                User(id_number=id_number, name=real_name, last_retrieve_time=0))
            db.session.commit()
        return {"status": "ok", "realname": real_name, "id_number": id_number}
    except KeyError:
        return {"status": "error", "msg": "无效图片"}, 400


# Guard

@app.route('/guard/validate', methods=['POST'])
@guard_required
def validate_qrcode():
    try:
        reason = request.json['reason']
        secret = request.json['secret']
        jwt_secret = re.match("instapass{(.*)}", secret).groups()[0]
        qr_json = decode(jwt_secret)
        if qr_json["type"] != "access":
            return {"status": "err", "msg": "无效 QR 码"}, 400
        guard = in_community(qr_json['community_id'], g.guard)
        if guard and guard.working_until > ts():
            dweller = Dweller.query.filter_by(id=qr_json['id']).first()
            dweller.last_access_time = ts()
            dweller.inside = not dweller.inside
            db.session.add(Log(community_id=qr_json['community_id'], user_id=qr_json['id'], temperature=37.0,
                               note=reason, access_time=ts(), inside='inside' if dweller.inside else 'outside'))
            db.session.commit()
            return {"status": "ok", "validation": "accepted"}
        else:
            return {"status": "err", "msg": "请求被拒绝"}, 403
    except KeyError:
        return params_not_given()
    except ExpiredSignatureError:
        return {"status": "err", "msg": "QR 码已过期"}, 400


@app.route('/generate/qrcode', methods=['POST'])
@guard_required
def generate_qrcode():
    try:
        community_id = request.json["community_id"]
        temp = request.json["temporary"]
        if temp:
            reason = request.json['reason']
        else:
            reason = ""
        return {
            "status": "ok",
            "last_refresh_time": ts(),
            "secret": f"instapass{{{create_qrcode_encode(community_id, temp, reason)}}}"
        }
    except KeyError:
        return params_not_given()


@app.route("/guard/checkin", methods=['POST'])
@guard_required
def guard_checkin():
    try:
        community_id = request.json["community_id"]
        guard = in_community(community_id, g.guard)
        if guard:
            guard.working_until = ts(12 * 3600)
            db.session.commit()
            return {"status": "ok"}
        else:
            return {"status": "err", "msg": "请求被拒绝"}, 403
    except KeyError:
        return params_not_given()


@app.route("/guard/checkout", methods=['POST'])
@guard_required
def guard_checkout():
    try:
        community_id = request.json["community_id"]
        guard = in_community(community_id, g.guard)
        if guard:
            guard.working_until = 0
            db.session.commit()
            return {"status": "ok"}
        else:
            return {"status": "err", "msg": "请求被拒绝"}, 403
    except KeyError:
        return params_not_given()

# Admin


@app.route('/admin/notify/release', methods=['POST'])
@admin_required
def release_notification():
    try:
        community_id = request.json["notification"]["community_id"]
        author = request.json["notification"]["author"]
        content = request.json["notification"]["content"]
        community = Community.query.filter_by(id=community_id).first()
        if not community or not in_community(community_id, g.admin):
            return {"status": "err", "msg": "请求被拒绝"}, 403
        db.session.add(Notice(community_id=community_id, author=author, content=content, create_time=ts(),
                              sender_id=g.admin[0].id))
        db.session.commit()
        return {"status": "ok"}
    except KeyError:
        return params_not_given()


@app.route('/admin/notifications', methods=['GET'])
@admin_required
def admin_retrieve_notifications():
    is_all = request.args.get("all")
    user = User.query.filter_by(id=g.id).first()
    communities = []
    community_map = {}
    for admin in g.admin:
        communities.append(admin.community_id)
        community_map[admin.community_id] = Community.query.filter_by(
            id=admin.community_id).first()
    last_retrieve_time = user.last_retrieve_time
    user.last_retrieve_time = ts()
    notifications = []
    if is_all is None:
        notices = db.session.query(Notice).filter(and_(
            Notice.create_time >= last_retrieve_time, Notice.community_id.in_(communities))).all()
    else:
        notices = db.session.query(Notice).filter(
            Notice.community_id.in_(communities)).all()
    for notice in notices:
        notifications.append({
            "community_id": notice.community_id,
            "community": community_map[notice.community_id].name,
            "address": community_map[notice.community_id].address,
            "content": notice.content,
            "author": notice.author,
            "release_time": notice.create_time
        })
    db.session.commit()
    return {"status": "ok", "last_retrieve_time": user.last_retrieve_time, "notifications": notifications}


@app.route('/admin/invite/<int:id>', methods=['GET'])
@admin_required
def admin_invite(id):
    if in_community(id, g.admin):
        return {"key": get_invitation(id)}
    else:
        return {"status": "error"}, 403


@app.errorhandler(405)
def method_not_allowed(error):
    return {"msg": "不允许的方法", "status": "err"}, 405


@app.errorhandler(500)
def internal_server_error(error):
    return {"msg": "服务器内部错误"}, 500


if __name__ == "__main__":
    app.config.from_object(config.dbinfo)
    db.init_app(app)
    app.run(host='0.0.0.0', port='8288')
