from main import db


# Time data is stored as timestamp(s).
# Binary data is base64-encoded.
# Json data is stored as string.

class User(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column('username', db.String(32))
    password = db.Column('password', db.String(32))


class Community(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(32))
    address = db.Column('address', db.String(1 << 12))


class Family(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    address = db.Column('address', db.String(1 << 12))


class Dweller(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.String(32))
    name = db.Column('real_name', db.String(32))
    id_number = db.Column('id_number', db.String(32))
    phone = db.Column('phone', db.String(32))
    email_address = db.Column('email_address', db.String(64))
    family_id = db.Column('family_id', db.Integer)
    last_access_time = db.Column('last_access_time', db.Integer)
    face_data = db.String('face_data', db.String(1 << 15))
    health_status = db.Column('health_status', db.Integer)


class Admin(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.String(32))
    level = db.Column('level', db.Integer)


class Monitor(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.String(32))
    working_until = db.Column('working_until', db.Integer)


class Notice(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.String(32))
    sender_id = db.Column('sender_id', db.Integer)
    title = db.String('title', db.String(64))
    content = db.Column('content', db.String(1 << 12))


class Log(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    community_id = db.Column('community_id', db.String(32))
    user_id = db.Column('user_id', db.Integer)
    access_time = db.Column('access_time', db.Integer)
    temperature = db.Column('temperature', db.Float)
    note = db.Column('note', db.String(128))
