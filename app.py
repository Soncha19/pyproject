from flask import Flask
from waitress import serve
app = Flask(__name__)
#route 123waitress-serve app:app

@app.route('/api/v1/hello-world-3')
def hello_world():  # put application's code here
    return "Hello world 3",200

if __name__ == '__main__':
    print("Server started")
    serve(app)
