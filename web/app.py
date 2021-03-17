#!/usr/bin/env python3

from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://db:27017')
db = client.SimilarityDB
users = db['users']

# users.delete_one({'username': 'admin'})
#
# users.insert({
#     'username': 'admin',
#     'password': generate_password_hash('Pa55word', salt_length=12),
#     'tokens': 1000000000,
#     'admin': True,
#     'created': datetime.now(),
#     'updated': datetime.now()
# })

status_codes = {
    'b_req': 400,
    'unauth': 401,
    'forbid': 403
}


def error(msg, type):
    response = jsonify({'error': msg})
    response.status_code = status_codes[type]
    return response


def get_user(username):
    return users.find_one({'username': username})


class RegisterUser(Resource):

    def post(self):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']

            if get_user(username):
                return error(f"'{username}' is unavailable", 'b_req')

            if not self._verify_password(password):
                msg = 'Password must have capitals, lowercase, and numbers'
                return error(msg, 'b_req')

            users.insert({
                'username': username,
                'password': generate_password_hash(password, salt_length=12),
                'tokens': 10,
                'admin': False,
                'created': datetime.now(),
                'updated': datetime.now()
            })

            return jsonify({'msg': f"'{username}' registered successfully"})
        except KeyError:
            return error('Missing required field', 'b_req')

    def _verify_password(self, password):
        upper = any(x.isupper for x in password)
        lower = any(x.islower for x in password)
        digit = any(x.isdigit for x in password)
        return upper and lower and digit


class GetUser(Resource):

    def post(self, uname):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']

            user_srch = get_user(uname)

            if not user_srch:
                return error(f"'{uname}' not found", 'b_req')

            user = get_user(username)

            if user and not user['admin']:
                return error('Unauthorised action', 'unauth')

            if not check_password_hash(user['password'], password):
                return error('Invalid credentials', 'b_req')

            return jsonify(str(user_srch))
        except KeyError:
            return error('Missing required field', 'b_req')


class DeleteUser(Resource):

    def post(self, uname):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']

            user_srch = get_user(uname)

            if not user_srch:
                return error(f"'{uname}' not found", 'b_req')

            user = get_user(username)

            if user and not user['admin']:
                return error('Unauthorised action', 'unauth')

            if not check_password_hash(user['password'], password):
                return error('Invalid credentials', 'b_req')

            users.delete_one({'username': user_srch['username']})

            return jsonify({'msg': f"'{uname}' deleted successfully"})
        except KeyError:
            return error('Missing required field', 'b_req')


class UpdateUser(Resource):

    def put(self, uname):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']
            new_password = data['new_password']

            user = get_user(username)

            if username != uname:
                return error('Forbidden', 'forbid')

            if not user:
                return error(f"'{uname}' not found", 'b_req')

            if not self._verify_password(new_password):
                msg = 'Password must have capitals, lowercase, and numbers'
                return error(msg, 'b_req')

            if not check_password_hash(user['password'], password):
                return error('Invalid credentials', 'b_req')

            if user['tokens'] == 0:
                return error('Out of tokens, buy more!', 'b_req')

            users.update(
                {'username': user['username']},
                {'$set': {
                    'password': generate_password_hash(new_password),
                    'tokens': user['tokens'] - 1,
                    'updated': datetime.now()
                }}
            )

            return jsonify({'msg': f"'{uname}' updated successfully"})
        except KeyError:
            return error('Missing required field', 'b_req')

    def _verify_password(self, password):
        upper = any(x.isupper for x in password)
        lower = any(x.islower for x in password)
        digit = any(x.isdigit for x in password)
        return upper and lower and digit


class GetToken(Resource):

    def post(self, uname):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']

            user = get_user(username)

            if username != uname:
                return error('Forbidden', 'forbid')

            if not user:
                return error(f"'{uname}' not found", 'b_req')

            if not check_password_hash(user['password'], password):
                return error('Invalid credentials', 'b_req')

            if user['tokens'] == 0:
                return error('Out of tokens, buy more!', 'b_req')

            users.update(
                {'username': user['username']},
                {'$set': {
                    'tokens': user['tokens'] - 1,
                    'updated': datetime.now()
                }}
            )

            return jsonify({'tokens': user['tokens']})
        except KeyError:
            return error('Missing required field', 'b_req')


class AddToken(Resource):

    def post(self, uname, amount):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']

            user_srch = get_user(uname)

            if not user_srch:
                return error(f"'{uname}' not found", 'b_req')

            user = get_user(username)

            if not user['admin']:
                return error('Unauthorised', 'unauth')

            if not check_password_hash(user['password'], password):
                return error('Invalid credentials', 'b_req')

            new_total = user_srch['tokens'] + amount

            users.update(
                {'username': user_srch['username']},
                {'$set': {
                    'tokens': new_total,
                    'updated': datetime.now()
                }}
            )

            return jsonify({'tokens': new_total})
        except KeyError:
            return error('Missing required field', 'b_req')


class Compare(Resource):

    def post(self):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']
            text1 = data['text1']
            text2 = data['text2']

            user = get_user(username)

            if not user:
                return error('Invalid credentials', 'b_req')

            if not check_password_hash(user['password'], password):
                return error('Invalid credentials', 'b_req')

            if user['tokens'] == 0:
                return error('Out of tokens, buy more!', 'b_req')

            users.update(
                {'username': user['username']},
                {'$set': {
                    'tokens': user['tokens'] - 1,
                    'updated': datetime.now()
                }}
            )

            nlp = spacy.load('en_core_web_sm')
            text1 = nlp(text1)
            text2 = nlp(text2)
            ratio = text1.similarity(text2)
            percent = str(ratio * 100)

            return jsonify({'msg': f'These documents have a {percent}% match'})
        except KeyError:
            return error('Missing required field', 'b_req')


class GetAll(Resource):

    def get(self):
        data = users.find({})
        user_data = []
        for user in data:
            user_data.append(str(user))
        return jsonify(user_data)


api.add_resource(RegisterUser, '/register')
api.add_resource(GetUser, '/user/<string:uname>')
api.add_resource(DeleteUser, '/user/delete/<string:uname>')
api.add_resource(UpdateUser, '/user/update/<string:uname>')
api.add_resource(GetToken, '/token/<string:uname>')
api.add_resource(AddToken, '/token/add/<string:uname>/<int:amount>')
api.add_resource(Compare, '/compare')
api.add_resource(GetAll, '/all')


if __name__ == '__main__':
    app.run(host='0.0.0.0')
