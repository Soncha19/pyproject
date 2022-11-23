from flask import Flask
from waitress import serve
from routes import *
# app = Flask(__name__)
#route 123waitress-serve app:app

# @app.route('/api/v1/hello-world-9')
# def hello_world():  # put application's code here
#     return "Hello world 9",200
# @app.route('/api/v1/hello-world-5')
# def hell_world():  # put application's code here
#     return "Hello world 5",200

if __name__ == '__main__':
    # print("Server started")
    serve(app)
