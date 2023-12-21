from datetime import datetime


import pyotp
from flask_login import UserMixin

from src import db, bcrypt, cipher_suite
from config import Config

roles_users = db.Table('roles_users',
                          db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                          db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
    # username = db.Column(db.String(80), unique=True, nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    _email = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    _name = db.Column(db.String(32), nullable=True)
    _phone = db.Column(db.String(32), nullable=True)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    created_on = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    is_two_factor_enabled = db.Column(db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.String(120), nullable=True)

    def __init__(self, email, password, name, phone, is_admin=False, is_confirmed=False):
        # self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.name = name
        self.phone = phone
        self.created_on = datetime.now()
        self.is_admin = is_admin
        self.is_confirmed = is_confirmed
        self.confirmed_on = datetime.now()
        self.secret_token = pyotp.random_base32()

    def get_auth_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(name=self.email, issuer_name=Config.APP_NAME)
    
    def verify_totp(self, user_otp):
        totp = pyotp.parse_uri(self.get_auth_uri())
        return totp.verify(user_otp)

    def __repr__(self):
        return f'<User {self.email}>'
    

    
    @property
    def name(self):
        return decrypt_data(self._name)

    @name.setter
    def name(self, name):
        print("name setter")
        self._name = encrypt_data(name)

    @property
    def phone(self):
        return decrypt_data(self._phone)

    @phone.setter
    def phone(self, phone):
        self._phone = encrypt_data(phone)
    
    @property
    def email(self):
        return decrypt_data(self._email)

    @email.setter
    def email(self, email):
        self._email = encrypt_data(email)


 
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=True)

class PasswordChanges(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    changed_on = db.Column(db.DateTime, nullable=False, server_default=db.func.now())



def encrypt_data(data):
    encrypted_data = cipher_suite.encrypt(data.encode('utf-8'))
    return encrypted_data

def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data