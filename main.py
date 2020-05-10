from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import config.dbinfo

app = Flask(__name__)
app.config.from_object(config.dbinfo)
db = SQLAlchemy(app)

from models.models import *

db.create_all()

# finish init. Maybe do code refactor in the future.

