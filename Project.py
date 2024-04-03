from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
import os
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

project = Flask(__name__)
project.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwks.db'
project.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
project.config['SECRET_KEY'] = os.getenv('NOT_MY_KEY', 'default_key')

db = SQLAlchemy(project)
limiter = Limiter(
    project,
    key_func=get_remote_address,
    default_limits=["10 per second"]
)
ph = PasswordHasher()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True)
    date_registered = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())
    last_login = db.Column(db.TIMESTAMP)

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(45), nullable=False)
    request_timestamp = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('auth_logs', lazy=True))

@project.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    password = os.urandom(16).hex()  # Generate a secure password
    password_hash = ph.hash(password)

    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({'password': password}), 201

@project.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if not user or not ph.verify(user.password_hash, password):
        return jsonify({'message': 'Authentication failed'}), 401

    auth_log = AuthLog(request_ip=request.remote_addr, user_id=user.id)
    db.session.add(auth_log)
    db.session.commit()

    return jsonify({'message': 'Authentication successful'}), 200

if __name__ == '__main__':
    db.create_all()
    project.run(debug=True)
