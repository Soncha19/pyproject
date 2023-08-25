from flask import Flask
from waitress import serve
from routes import *
from flask_cors import CORS
from flask_jwt_extended import JWTManager
jwt = JWTManager(app)
app.config["JWT_SECRET_KEY"] = "secret"
CORS(app)
@app.route('/api/v1/hello-world-62')
def hello_world():  # put application's code here
    return "Hello world 62",200

if __name__ == '__main__':
    # print("Server started")
    serve(app)
