HOST = '127.0.0.1'
PORT = '3306'
DATABASE = 'instadb'
USERNAME = 'instapass'
PASSWORD = open('config/password.txt').read()

DB_URI = "mysql+pymysql://{username}:{password}@{host}:{port}/{db}?charset=utf8".format(username=USERNAME,
                                                                                        password=PASSWORD,
                                                                                        host=HOST,
                                                                                        port=PORT,
                                                                                        db=DATABASE)

SQLALCHEMY_DATABASE_URI = DB_URI
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = True
SQLALCHEMY_POOL_RECYCLE = 1800
