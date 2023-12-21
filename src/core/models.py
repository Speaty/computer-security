from datetime import datetime

from src import db


class UserSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(120), nullable=False)
    submission = db.Column(db.String(1000), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    filename = db.Column(db.String(250), nullable=True)
    contact = db.Column(db.String(250), nullable=False)
    

    def __init__(self, user_id, submission, contact, subject, filename=None, ):
        self.user_id = user_id
        self.subject = subject
        self.submission = submission
        self.filename = filename
        self.created_on = datetime.now()
        self.contact = contact