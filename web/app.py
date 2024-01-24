"""
APP DE TOKENS
Registro de usuario 0 tokens
Cada usuario obtiene 10 tokens
Almacenar una oracion 1 token
Pedir que lea la oracion guardada 1 token
"""
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SentencesDatabase
users = db["Users"]

class Register(Resource):
    def post(self):
        # Se va a guardar la data otorgada por el user
        postedData = request.get_json()

        # Se almacena la data
        username = postedData["username"]
        password = postedData["password"]


        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Almacena el usuario y contraseña en la DB
        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Sentence": "",
            "Tokens":6
        })

        retJson = {
            "status": 200,
            "msg": "Te registraste correctamente en la API"
        }
        return jsonify(retJson)

def verifyPw(username, password):
    hashed_pw = users.find({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def countTokens(username):
    tokens = users.find({
        "Username":username
    })[0]["Tokens"]
    return tokens

class Store(Resource):
    def post(self):
        # Obtenemos la postedData
        postedData = request.get_json()

        #Se lee la postedData
        username = postedData["username"]
        password = postedData["password"]
        sentence = postedData["sentence"]

        # Verificamos que el usuario y contraseña coincidan
        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status":302
            }
            return jsonify(retJson)
        # Verificamos que el usuario tenga Tokens disponibles
        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
                "status": 301
            }
            return jsonify(retJson)

        # Almacenamos la oracion, se le cobra 1 Token y si todo va bien tira 200 OK
        users.update_one({
            "Username":username
        }, {
            "$set":{
                "Sentence":sentence,
                "Tokens":num_tokens-1
                }
        })

        retJson = {
            "status":200,
            "msg":"Oracion guardada exitosamente"
        }
        return jsonify(retJson)

class Get(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        # Verificamos el usuario y contraseña
        correct_pw = verifyPw(username, password)
        if not correct_pw:
            retJson = {
                "status":302
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
                "status": 301
            }
            return jsonify(retJson)

        # Le cobramos al usuario 1 Token
        users.update_one({
            "Username":username
        }, {
            "$set":{
                "Tokens":num_tokens-1
                }
        })


        # Buscamos la oracion que coincuda con el usuario y lo mostramos por pantalla
        sentence = users.find({
            "Username": username
        })[0]["Sentence"]
        retJson = {
            "status":200,
            "sentence": str(sentence)
        }

        return jsonify(retJson)

api.add_resource(Register, '/register')
api.add_resource(Store, '/store')
api.add_resource(Get, '/get')


if __name__=="__main__":
    app.run(host='0.0.0.0')

