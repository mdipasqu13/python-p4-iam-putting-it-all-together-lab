#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.json
        try:
            new_user = User(
                username = data.get('username'),
                image_url = data.get('image_url'),
                bio = data.get('bio')

            )  
            new_user.password_hash = data.get('password')

            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id

            return make_response(new_user.to_dict(only=['id', 'username', 'image_url', 'bio']), 201)
        except:
            return make_response({'error': ['validation errors']}, 422)

class CheckSession(Resource):
    def get(self):
        cookie_id = session.get('user_id')
        if cookie_id:
            user = User.query.filter_by(id=cookie_id).first()
            if user:
                return user.to_dict(only=['id', 'username', 'image_url', 'bio'])
        return {'message': 'failed to authenticate'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get('username')).first()
        password = data.get('password')
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(only=['id', 'username', 'image_url', 'bio'])
        return {'message': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        cookie_id = session.get('user_id')
        if cookie_id:
            user = User.query.filter_by(id=cookie_id).first()
            if user:
                session['user_id'] = None
                return {}, 204
        else:
            return {}, 401

class RecipeIndex(Resource):
    def get(self):
        cookie_id = session.get('user_id')
        if cookie_id:
            user = User.query.filter_by(id=cookie_id).first()
            if user:
                recipes = [recipe.to_dict(only=['title', 'instructions', 'minutes_to_complete', 'user']) for recipe in Recipe.query.all()]
                return recipes
        else:
            return {'error': 'Unauthorized attempt'}, 401
        
    def post(self):
        cookie_id = session.get('user_id')
        if cookie_id:
            user = User.query.filter_by(id=cookie_id).first()
            if user:
                try:
                    data = request.json
                    new_recipe = Recipe(
                        title = data.get('title'),
                        instructions = data.get('instructions'),
                        minutes_to_complete = data.get('minutes_to_complete'),
                        user_id = cookie_id
                    )

                    db.session.add(new_recipe)
                    db.session.commit()

                    return new_recipe.to_dict(only=['title', 'instructions', 'minutes_to_complete', 'user']), 201
                except:
                    return {'error': ['validation errors']}, 422
        else:
            return {'error': 'Unauthorized attempt'}, 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)