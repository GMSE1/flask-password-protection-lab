#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    def post(self):
        # 1. Get username and password from request body
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # 2. Create new user (password_hash setter automatically hashes the password)
        user = User(username=username)
        user.password_hash = password  # This triggers bcrypt hashing via our setter!
        
        # 3. Save to database
        db.session.add(user)
        db.session.commit()
        
        # 4. Log user in by setting session
        session['user_id'] = user.id
        
        # 5. Return user object with 201 Created status
        return UserSchema().dump(user), 201
    
class CheckSession(Resource):
    def get(self):
        # Check if user_id exists in session
        user_id = session.get('user_id')
        
        if user_id:
            # User is authenticated - find and return user
            user = User.query.filter_by(id=user_id).first()
            return UserSchema().dump(user), 200
        
        # User is NOT authenticated - return empty response
        return {}, 204

class Login(Resource):
    def post(self):
        # 1. Get username and password from request
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # 2. Find user by username
        user = User.query.filter_by(username=username).first()
        
        # 3. Verify user exists and password is correct
        if user and user.authenticate(password):
            # Password is correct - log user in
            session['user_id'] = user.id
            return UserSchema().dump(user), 200
        
        # Invalid credentials
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        # Clear user_id from session (log user out)
        session['user_id'] = None
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')  # Add this
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
