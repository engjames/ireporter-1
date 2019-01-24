from flask import request, jsonify
from api.authentication.auth import generate_token
from werkzeug.security import generate_password_hash, check_password_hash
from api.models.user_incident import User, user_data
from api.utility.validation import UserValidation
from api.database.db import DatabaseConnection
from datetime import datetime, timedelta

db_conn = DatabaseConnection()


class UserController:
    def __init__(self):
        pass

    def signup_user(self):
        """Method for user sign up"""
        data = request.get_json()
        first_name = data.get('firstname')
        last_name = data.get('lastname')
        other_names = data.get('othernames')
        user_email = data.get('email')
        phone_number = data.get('phone_number')
        user_name = data.get('username')
        Password = data.get('password')
        registered = datetime.now()
        admin = data.get("is_admin")
        if not first_name or not last_name or not\
                other_names or not user_email or not phone_number or not \
                user_name or not Password or not admin:
            return jsonify({
                'status': 400,
                'error': 'A required field is either missing or empty'
            }), 400

        if not UserValidation.validate_phone_number(phone_number):
            return jsonify({
                'status': 400,
                'error': 'Only numbers are allowed for the phone number field'
            }), 400
        if not UserValidation.validate_user_password(Password):
            return jsonify({
                'status': 400,
                'error': 'Password must be atleast 8 characters and should have atleast one number and one capital letter'
            }), 400
        user = User(first_name, last_name, other_names, user_email,
                    phone_number, user_name, registered, generate_password_hash(Password), admin)

        if db_conn.email_dup(user_email):
            return jsonify({'status': 400,
                            'error': 'User account already exists'}), 400
        db_conn.register_user(
            first_name, last_name, other_names, user_email, phone_number,
            user_name, registered, generate_password_hash(Password), admin
        )

        return jsonify({"data": [{
            "status": 201,
            "message": "user created successfully",
        }]}), 201

    def login_user(self):
        """Method for user login"""
        login_data = request.get_json()
        login_email = login_data.get('email')
        login_password = login_data.get('password')
        if not UserValidation.validate_user_password(login_password):
            return jsonify({
                'status': 400,
                'error': 'Password must be atleast 8 characters and should have atleast one number and one capital letter'
            }), 400
        if not login_email:
            return jsonify({"Message": "Please enter your credentials"})
        if not db_conn.login_user(login_email):
            return jsonify({
                "Error": "User account does not exist",
                "status": 400
            }), 400
        user = db_conn.login_user(login_email)
        if check_password_hash(user["password"], login_password):
            access_token = generate_token(1)
            return jsonify({'access-token': access_token,   "Message": "User successfully logged in"}), 201
        return jsonify({
            "Error": "Invalid credentials"
        })
