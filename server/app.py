#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api, bcrypt 
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        errors = []

        # basic validations
        if not username or username.strip() == "":
            errors.append("Username is required.")
        if not password or password.strip() == "":
            errors.append("Password is required.")

        if errors:
            return {"errors": errors}, 422


        try:
            # create user
            new_user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            new_user.password_hash = password  # triggers bcrypt hashing

            db.session.add(new_user)
            db.session.commit()

            # save user in session
            session["user_id"] = new_user.id

            return {
                "id": new_user.id,
                "username": new_user.username,
                "image_url": new_user.image_url,
                "bio": new_user.bio
            }, 201

        except Exception as e:
            # handles uniqueness and validation errors
            db.session.rollback()
            return jsonify({"errors": [str(e)]}), 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }, 200
            else:
                # session has an invalid user_id
                return {"error": "Invalid session"}, 401

        return {"error": "Unauthorized"}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        # Find the user by username
        user = db.session.query(User).filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user._password_hash, password):
            # Save the user ID in the session
            session["user_id"] = user.id

            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200

        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")

        if user_id:
            session.pop("user_id", None)
            return {}, 204

        return {"error": "Unauthorized"}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        # Fetch all recipes
        recipes = Recipe.query.all()

        recipe_list = []
        for recipe in recipes:
            recipe_list.append({
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            })

        return recipe_list, 200
    
    def post(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json() or {}

        title = data.get("title")
        instructions = data.get("instructions")
        minutes_to_complete = data.get("minutes_to_complete")

        # Basic validations
        errors = []
        if not title:
            errors.append("Title is required")
        if not instructions or len(instructions) < 50:
            errors.append("Instructions must be at least 50 characters long")
        if not minutes_to_complete:
            errors.append("Minutes to complete is required")

        if errors:
            return {"errors": errors}, 422

        try:
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()

            return {
                "id": new_recipe.id,
                "title": new_recipe.title,
                "instructions": new_recipe.instructions,
                "minutes_to_complete": new_recipe.minutes_to_complete,
                "user": {
                    "id": new_recipe.user.id,
                    "username": new_recipe.user.username,
                    "image_url": new_recipe.user.image_url,
                    "bio": new_recipe.user.bio
                }
            }, 201

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Invalid recipe data"]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)