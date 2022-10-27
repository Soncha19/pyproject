from flask import request, Flask
from models import *
import json

app = Flask(__name__)


@app.route('/advertisement', methods=['GET'])
def find_advert_by_id():
	args = request.args
	advert_id = args.get('advert_id')
	ads = Session.query(Advertisement).filter(Advertisement.id == advert_id)
	return json.dumps(ads.to_dict())