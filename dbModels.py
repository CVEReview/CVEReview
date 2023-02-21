from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON
 
db = SQLAlchemy()
 
class cve(db.Model):
    cveId = db.Column(db.String, primary_key = True)
    data = db.Column(JSON)
    epss = db.Column(db.Integer())
 