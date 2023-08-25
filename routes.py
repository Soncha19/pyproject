from flask import request, Flask, make_response
from models import *
import json
from flask_bcrypt import generate_password_hash
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt import current_identity
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
app = Flask(__name__)
auth = HTTPBasicAuth()

@app.route('/category/findAll', methods=['GET'])

def find_all_category():



    categories = session.query(Category)
    return jsonify([i.to_dict() for i in categories])
@app.route('/advertisement', methods=['Post'])
@auth.login_required
def new_advert():
    args = request.get_json()
    # authorization = request.authorization
    # if not verify_password(authorization):
    # 	return "Not logged in", 401
    try:

        advert_schema = AdvertSchema()
        ad1 = advert_schema.load(args, session=session)
        user = session.query(User).filter(User.username == request.authorization.username).first()
        ad1.user = user
        if session.query(Category).filter(Category.id == ad1.category_id).count() == 0:
            return "Category doesn't exists", 405
        session.add(ad1)
        session.commit()
        return advert_schema.dump(ad1), 200
    except ValidationError as err:
        return jsonify(err.messages), 405


@app.route('/category', methods=['Post'])
@auth.login_required
def new_category():
    args = request.get_json()

    # authorization = request.authorization
    # if not verify_password(authorization.username,authorization.password):
    # 	return "Not logged in", 401
    try:

        category_schema = CategorySchema()
        category1 = category_schema.load(args, session=session)
        session.add(category1)
        session.commit()

        return category_schema.dump(category1), 200

    except ValidationError as err:

        return err.messages, 400


@app.route('/advertisement', methods=['GET'])
@auth.login_required
def find_advert_by_id():
    args = request.args
    logged_in = False
    authorization = request.authorization
    if veryfy_password(authorization.username,authorization.password):
        logged_in = True
    try:
        advert_id = args.get('advert_id')
        if session.query(Advertisement).filter(Advertisement.id == advert_id).count() == 0:
            return "Ad doesn't exists", 400
        ads = session.query(Advertisement).filter(Advertisement.id == advert_id).first()
        if (not ads.is_global) or (not logged_in):
            return "You don't have access", 403
        ad_schema = AdvertSchema()
        return ad_schema.dumps(ads), 200
    except ValidationError as err:
        return err.messages, 401


@app.route('/advertisement/findByAccess', methods=['GET'])
@auth.login_required
def find_advert_by_access():
    args = request.args
    logged_in = False
    authorization = request.authorization
    if veryfy_password(authorization.username, authorization.password):
        logged_in = True
    try:
        advert_access = args.get('advert_access')
        if (int(advert_access) == 0) and (not logged_in):
            return "You don't have access", 403
        if (int(advert_access) == 0):
            user = session.query(User).filter(User.username == authorization.username).first()
            ads = session.query(Advertisement).filter(Advertisement.is_global == advert_access).filter(Advertisement.user_id == User.id, User.address == user.address)
        else:
            ads = session.query(Advertisement).filter(Advertisement.is_global == advert_access)
        ad_schema = AdvertSchema()
        return json.dumps([ad_schema.dump(i) for i in ads]), 200
    except ValidationError as err:
        return err.messages, 401


@app.route('/advertisement/findByCategory', methods=['GET'])
@auth.login_required
def find_advert_by_category():
    args = request.args
    logged_in = False
    authorization = request.authorization
    if veryfy_password(authorization.username, authorization.password):
        logged_in = True
    try:
        advert_category = args.get('advert_category')

        if session.query(Advertisement).filter(Advertisement.category_id == Category.id, Category.name == advert_category).count() == 0:
            return "Category doesn't exists", 400

        if logged_in:
            user = session.query(User).filter(User.username == authorization.username).first()
            ads = session.query(Advertisement).filter(Advertisement.category_id == Category.id, Category.name == advert_category,user.id==Advertisement.user_id,User.address==user.address)

            ads1 = session.query(Advertisement).filter(Advertisement.category_id == Category.id, Category.name == advert_category).filter(Advertisement.is_global == 1)
        results = ads.union_all(ads1).all()
        ad_schema = AdvertSchema()
        return json.dumps([ad_schema.dump(i) for i in results]), 200
    except ValidationError as err:
        return err.messages, 401


@app.route('/advertisement/findByUser', methods=['GET'])
@auth.login_required
def find_advert_by_user():
    logged_in = False
    authorization = request.authorization
    # if verify_password(authorization):
    # 	logged_in = True
    try:
        args = request.args
        advert_user = args.get('advert_user')
        if (session.query(Advertisement).filter(Advertisement.user_id == User.id,
                                                User.username == advert_user).count() == 0):
            return "Ads doesn't exists", 400
        user = Session.query(User).filter(User.username == authorization.username).first()
        if  (user.username != advert_user)or (not logged_in):
            return "You don't have access", 403

        if logged_in:
            ads = Session.query(Advertisement).filter(Advertisement.user_id == User.id, User.username == advert_user)
        if not logged_in:
            ads = Session.query(Advertisement).filter(Advertisement.user_id == User.id, User.username == advert_user).filter(Advertisement.status == 1)

        ad_schema = AdvertSchema()
        return json.dumps([ad_schema.dump(i) for i in ads]), 200
    except ValidationError as err:
        return err.messages

Session = sessionmaker(bind=engine)
@app.route('/user/register', methods=['Post'])
def create_user():
        session_ = Session()
        args = request.get_json()
        try:
            user_schema = UserSchema()
            user = user_schema.load(args, session=session_)
            if not (session.query(User).filter(User.username == user.username).count() == 0):
                session_.close()
                return {"message": "Not correct data provided"}, 400
            user.password = generate_password_hash(user.password)
            session_.add(user)
            session_.commit()
            res = user_schema.dump(user)
            session_.commit()
            session_.close()
            return res, 200
        except ValidationError as err:
            session_.close()
            return {"message": "Not correct data provided"}, 400
    # 	return user_schema.dump(user1)
    # except ValidationError as err:
    # 	return {"message": "Not correct data provided"}, 400


# args = request.get_json()
# user = User(**args)
# Session.add(user)
# Session.commit()
# return user.to_dict()


@app.route('/user/username', methods=['GET'])
def find_user_by_username():
    session = Session()
    args = request.args
    #authorization = request.authorization
    # if not verify_password(authorization):
    # 	session.close()
    # 	return "Not logged in", 401
    try:
        user_username = args.get('user_username')
        if session.query(User).filter(User.username == user_username).count() == 0:
            session.close()
            return "User doesn't exist", 404
        user = session.query(User).filter(User.username == user_username).first()
        user_schema = UserSchema()
        return user_schema.dump(user), 200
        session.commit()
        session.close()
    except ValidationError as err:
        session.close()
        return err.messages, 400
@app.route('/user/', methods=['GET'])
@auth.login_required
def find_user_by_id():
    args = request.args
    session = Session()
    #authorization = request.authorization
    # if not veryfy_password(request.authorization.username, request.authorization.password):
    # 	#return "Not logged in", 401
    try:
        user_id = args.get('user_id')
        if session.query(User).filter(User.id == user_id).count() == 0:
            return "User doesn't exist", 404
        user = session.query(User).filter(User.id == user_id).first()

        user_schema = UserSchema()
        return user_schema.dump(user), 200
    except ValidationError as err:
        return err.messages, 400
# @app.route("/login", methods=["POST"])
# def login():
# 	auth = request.get_json()
#
# 	try:
# 		username = auth['username']
# 		password = auth['password']
# 	except:
# 		return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
#
# 	session = Session()
# 	users = session.query(User).filter(User.username == username)
# 	if users.count() == 0:
# 		return jsonify({'response': 'user with such email not found'}), 404
# 	us = users.first()
#
# 	if check_password_hash(us.password, password):
# 		token = create_access_token(identity=us.username)
# 		res = {
# 			"id": us.id,
# 			"first_name": us.first_name,
# 			"last_name": us.last_name,
# 			"username": us.username,
# 			"address": us.address,
#
# 			"phone_number": us.phone_number,
# 			"email": us.email,
# 			"token": token
# 		}
# 		session.commit()
# 		session.close()
# 		return jsonify(res), 200
# 	return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
@app.route('/login', methods=['POST'])

def login():
    auth = request.get_json()

    username = auth['username']
    password = auth['password']

    if not username or not password:
        return jsonify({'message': 'Username or password is missing'}), 400

    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        session.close()
        return jsonify({'message': 'Invalid username or password'}), 401

    session.close()
    return jsonify({'message': 'Logged in successfully'}),200

@app.route('/user/', methods=['PUT'])
@auth.login_required
def update_user():
    session = Session()
    arg = request.args
    authorization = request.authorization

    try:
        user_id = arg.get('user_id')
        if session.query(User).filter(User.id == user_id).count() == 0:
            return {"message": "User doesn't exists"}, 405
        # return "User doesn't exists", 405
        args = request.get_json()

        user = session.query(User).filter(User.id == user_id).first()
        if user.username != authorization.username:
            return "You don't have access to this user", 403
        users1 = session.query(User).filter(User.id == user_id).first()
        user_schema = UserSchema()
        user1 = user_schema.load(args, session=session)
        # if user1.username!=users1.username:
        # 	user1.username = "123"
        session.commit()

        session.query(User).filter(User.id == user_id).update(args)

        session.commit()
        users = session.query(User).filter(User.id == user_id).first()

        session.close()
        return user_schema.dump(users)
    except ValidationError as err:
        session.close()
        return jsonify(err.messages), 400


@app.route('/advertisement', methods=['PUT'])
@auth.login_required
def update_advert():
    arg = request.args

    authorization = request.authorization
    # if not verify_password(authorization):
    # 	return "Not logged in", 401
    try:
        ad_id = arg.get('ad_id')
        if session.query(Advertisement).filter(Advertisement.id == ad_id).count() == 0:
            return {"message": "Advert doesn't exists"}, 404

        args = request.get_json()
        ad_schema = AdvertSchema()
        ad1 = ad_schema.load(args, session=session)

        ad = Session.query(Advertisement).filter(Advertisement.id == ad_id).first()
        user = session.query(User).filter(User.id == ad.user_id).first()
        if user.username != authorization.username:
            return "You don't have access to this user", 403

        if session.query(User).filter(User.id == ad1.user_id).count() == 0:
            return {"message": "User doesn't exists"}, 404
        if session.query(Category).filter(Category.id == ad1.category_id).count() == 0:
            return {"message": "Category doesn't exists"}, 404
        session.query(Advertisement).filter(Advertisement.id == ad_id).update(args)
        users = session.query(Advertisement).filter(Advertisement.id == ad_id).first()
        session.commit()
        return ad_schema.dump(ad1), 200
    except ValidationError as err:
        return err.messages


@app.route('/user/', methods=['DELETE'])
@auth.login_required
def delete_user():
    args = request.args
    session = Session()
    #authorization = request.authorization
    # if not verify_password(authorization):
    # 	return "Not logged in", 401
    try:
        user_id = args.get('user_id')
        if session.query(User).filter(User.id == user_id).count() == 0:
            session.close()
            return {"message": "User doesn't exists"}, 404

        user = session.query(User).filter(User.id == user_id).first()
        # if user.username != authorization.username:
        # 	return "You don't have access to this user", 403

        if session.query(Advertisement).filter(Advertisement.user_id == user_id).count() != 0:
            return "Delete the advert firstly", 404
        user = session.query(User).filter(User.id == user_id)[0].to_dict()

        session.query(User).filter(User.id == user_id).delete()
        session.commit()
        session.close()
        return "user is deleted", 200
    except ValidationError as err:
        session.close()
        return err.messages, 400


@app.route('/category', methods=['DELETE'])
@auth.login_required
def delete_category():
    args = request.args
    # authorization = request.authorization
    # if not verify_password(authorization):
    # 	return "Not logged in", 401
    try:
        category_id = args.get('category_id')
        if session.query(Category).filter(Category.id == category_id).count() == 0:
            return "Category doesn't exists", 405
        if session.query(Advertisement).filter(Advertisement.category_id == category_id).count() != 0:
            return "Delete the advert firstly", 405

        category = session.query(Category).filter(Category.id == category_id)[0].to_dict()

        Session.query(Category).filter(Category.id == category_id).delete()
        Session.commit()
        return "category is deleted"
    except ValidationError as err:
        return jsonify(err.messages), 400


@app.route('/advertisement', methods=['DELETE'])
@auth.login_required
def delete_advert():
    args = request.args
    # authorization = request.authorization
    # if not verify_password(authorization):
    # 	return "Not logged in", 401
    try:
        ad_id = args.get('ad_id')
        if session.query(Advertisement).filter(Advertisement.id == ad_id).count() == 0:
            return {"message": "Advert doesn't exists"}, 405

        ad = Session.query(Advertisement).filter(Advertisement.id == ad_id).first()
        user = session.query(User).filter(User.id == ad.user_id).first()
        # if user.username != authorization.username:
        # 	return "You don't have access to this user", 403


        Session.query(Advertisement).filter(Advertisement.id == ad_id).delete()
        Session.commit()
        return "advert is deleted"
    except ValidationError as err:
        return err.messages


@app.route('/category', methods=['GET'])
def find_category_by_id():
    args = request.args
    try:
        c_id = args.get('c_id')
        if session.query(Category).filter(Category.id == c_id).count() == 0:
            return "Category doesn't exists", 404
        ads = Session.query(Category).filter(Category.id == c_id).first()
        ad_schema = CategorySchema()
        return ad_schema.dumps(ads), 200
    except ValidationError as err:
        return err.messages, 400

@auth.verify_password
def veryfy_password(username,password):
    session=Session()
    users=session.query(User).filter(User.username==username)
    if users.count()==0:
        return False
    if not check_password_hash(users.first().password,password):
        return False
    return True
# @auth.verify_password
# def verify_password(authorization):
# 	if not authorization or not authorization.username or not authorization.password:
# 		return False
# 	session_ = Session()
# 	users = session_.query(User).filter(User.username == authorization.username)
# 	if users.count() == 0:
# 		session_.close()
# 		return False
# 	if not check_password_hash(users.first().password, authorization.password):
# 		session_.close()
# 		return False
# 	session_.close()
# 	return True

