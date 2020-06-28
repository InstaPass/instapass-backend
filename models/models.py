from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# Time data is stored as timestamp(s).
# Binary data is base64-encoded.
# Json data is stored as string.

class User(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column('username', db.String(32))
    password = db.Column('password', db.String(32))
    last_retrieve_time = db.Column('last_retrieve_time', db.Integer)
    name = db.Column('real_name', db.String(32))
    id_number = db.Column('id_number', db.String(32))
    nickname = db.Column('nickname', db.String(32))
    phone = db.Column('phone', db.String(32))
    email_address = db.Column('email_address', db.String(64))


class Community(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(32))
    address = db.Column('address', db.String(1 << 12))


class Family(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    address = db.Column('address', db.String(1 << 12))


class Dweller(db.Model):
    auto = db.Column('auto', db.Integer, primary_key=True)
    id = db.Column('id', db.Integer)
    community_id = db.Column('community_id', db.Integer)
    family_id = db.Column('family_id', db.Integer)
    last_access_time = db.Column('last_access_time', db.Integer)
    inside = db.Column('inside', db.Boolean)
    health_status = db.Column('health_status', db.Integer)
    temp = db.Column('temp', db.Boolean)  # 0: dweller, 1: temp user


class Admin(db.Model):
    auto = db.Column('auto', db.Integer, primary_key=True)
    id = db.Column('id', db.Integer)
    community_id = db.Column('community_id', db.Integer)
    level = db.Column('level', db.Integer)


class Monitor(db.Model):
    auto = db.Column('auto', db.Integer, primary_key=True)
    id = db.Column('id', db.Integer)
    community_id = db.Column('community_id', db.Integer)
    working_until = db.Column('working_until', db.Integer)


class Notice(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.Integer)
    sender_id = db.Column('sender_id', db.Integer)
    author = db.Column('author', db.String(64))
    content = db.Column('content', db.String(1 << 12))
    create_time = db.Column("create_time", db.Integer)


class Log(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.Integer)
    inside = db.Column('inside', db.String(11))
    user_id = db.Column('user_id', db.Integer)
    access_time = db.Column('access_time', db.Integer)
    temperature = db.Column('temperature', db.Float)
    note = db.Column('note', db.String(128))


class InviteKey(db.Model):
    auto = db.Column('auto', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.Integer)
    key = db.Column('key', db.String(64))
    used = db.Column('used', db.Boolean)
