from flask import request, Flask,jsonify,Blueprint
from models import *
import json
from flask_bcrypt import generate_password_hash
app = Flask(__name__)

@app.route('/advertisement', methods=['Post'])
def new_advert():
    args = request.get_json()
    try:
        advert_schema = AdvertSchema()
        ad1 = advert_schema.load(args,session=session)
        if (session.query(User).filter(User.id == ad1.user_id).count() == 0):
            return "User doesn't exists",405
        if (session.query(Category).filter(Category.id == ad1.category_id).count() == 0):
            return "Category doesn't exists",405
        Session.add(ad1)
        Session.commit()
        return advert_schema.dump(ad1)
    except ValidationError as err:
         return jsonify(err.messages),405
@app.route('/category', methods=['Post'])
def new_category():
    args = request.get_json()
    try:
        category_schema = CategorySchema()
        category1 = category_schema.load(args,session=session)
        Session.add(category1)
        Session.commit()
        return category_schema.dump(category1)
    except ValidationError as err:
         return err.messages

@app.route('/advertisement', methods=['GET'])
def find_advert_by_id():
    args = request.args
    try:
        advert_id = args.get('advert_id')
        if (session.query(Advertisement).filter(Advertisement.id == advert_id).count() == 0):
            return "Ad doesn't exists", 400
        ads = Session.query(Advertisement).filter(Advertisement.id == advert_id).first()
        ad_schema=AdvertSchema()
        return ad_schema.dumps(ads)
    except ValidationError as err:
        return err.messages
@app.route('/advertisement/findByAccess', methods=['GET'])
def find_advert_by_access():
    args = request.args
    try:
        advert_access = args.get('advert_access')
        if (session.query(Advertisement).filter(Advertisement.status == advert_access).count() == 0):
            return "Status doesn't exists", 400
        ads = Session.query(Advertisement).filter(Advertisement.status == advert_access)
        ad_schema = AdvertSchema()
        return json.dumps([ad_schema.dump(i) for i in ads])
    except ValidationError as err:
        return err.messages
@app.route('/advertisement/findByCategory', methods=['GET'])
def find_advert_by_category():
    args = request.args
    try:
        advert_category = args.get('advert_category')
        if (session.query(Advertisement).filter(Advertisement.category_id == Category.id, Category.name==advert_category).count() == 0):
            return "Category doesn't exists", 400
        ads = Session.query(Advertisement).filter(Advertisement.category_id == Category.id, Category.name==advert_category)
        ad_schema = AdvertSchema()
        return json.dumps([ad_schema.dump(i) for i in ads])
    except ValidationError as err:
        return err.messages
@app.route('/advertisement/findByUser', methods=['GET'])
def find_advert_by_user():
    try:
        args = request.args
        advert_user = args.get('advert_user')
        if (session.query(Advertisement).filter(Advertisement.user_id == User.id, User.username ==advert_user).count() == 0):
            return "User doesn't exists", 400
        ads = Session.query(Advertisement).filter(Advertisement.user_id == User.id, User.username ==advert_user)
        ad_schema = AdvertSchema()
        return json.dumps([ad_schema.dump(i) for i in ads])
    except ValidationError as err:
        return err.messages
@app.route('/user/register', methods=['Post'])
def new_user():
    args = request.get_json()

    try:
        user_schema = UserSchema()
        user1 = user_schema.load(args, session=session)
        if "@" not in user1.email :
            return {"message":"Invalid email"}, 405
        if args.pop(user1.phone_number, False):
            return {"message":"Invalid phone number"}, 405
        user1.password = generate_password_hash(user1.password)
        Session.add(user1)
        Session.commit()
        return user_schema.dump(user1)
    except ValidationError as err:
         return {"message": "Not correct data provided"}, 422


    # args = request.get_json()
    # user = User(**args)
    # Session.add(user)
    # Session.commit()
    # return user.to_dict()
@app.route('/user/username', methods=['GET'])
def find_user_by_username():
    args = request.args
    try:
        user_username = args.get('user_username')
        if (session.query(User).filter(User.username == user_username).count() == 0):
            return "User doesn't exists",405
        user = Session.query(User).filter(User.username == user_username).first()
        user_schema=UserSchema()

        return user_schema.dumps(user)
    except ValidationError as err:
        return err.messages
@app.route('/user/username', methods=['PUT'])
def update_user():

    arg = request.args
    try:
        user_id = arg.get('user_id')
        if  (session.query(User).filter(User.id == user_id).count() == 0):
            return {"message": "User doesn't exists"}, 405
            #return "User doesn't exists", 405
        args=request.get_json()
        user_schema = UserSchema()
        user1 = user_schema.load(args, session=session)
        session.query(User).filter(User.id == user_id).update(args)

        session.commit()
        users = session.query(User).filter(User.id == user_id).first()
        return user_schema.dump(users)
    except ValidationError as err:
        return jsonify(err.messages), 400
@app.route('/advertisement', methods=['PUT'])
def update_advert():

    arg = request.args
    try:
        adid = arg.get('adid')
        if  (session.query(Advertisement).filter(Advertisement.id == adid).count() == 0):
            return {"message": "Advert doesn't exists"}, 404

        args=request.get_json()
        ad_schema = AdvertSchema()
        ad1 = ad_schema.load(args, session=session)
        if  (session.query(User).filter(User.id == ad1.user_id).count() == 0):
            return {"message": "User doesn't exists"}, 404
        if  (session.query(Category).filter(Category.id == ad1.category_id).count() == 0):
            return {"message": "Category doesn't exists"}, 404
        session.query(Advertisement).filter(Advertisement.id == adid).update(args)
        users = session.query(Advertisement).filter(Advertisement.id == adid).first()
        session.commit()
        return ad_schema.dump(ad1)
    except ValidationError as err:
        return err.messages
@app.route('/user/username', methods=['DELETE'])
def delete_user():
    args = request.args
    try:
        user_id = args.get('user_id')
        if  (session.query(User).filter(User.id == user_id).count() == 0):
            return {"message": "User doesn't exists"}, 404
        if  (session.query(Advertisement).filter(Advertisement.user_id == user_id).count() != 0):
            return "Delete the advert firstly",404
        user = Session.query(User).filter(User.id == user_id)[0].to_dict()

        Session.query(User).filter(User.id == user_id).delete()
        Session.commit()
        return "user is deleted"
    except ValidationError as err:
        return err.messages
@app.route('/category', methods=['DELETE'])
def delete_category():
    args = request.args
    try:
        categoryid = args.get('categoryid')
        if  (session.query(Category).filter(Category.id == categoryid).count() == 0):
            return "Category doesn't exists",405
        if  (session.query(Advertisement).filter(Advertisement.category_id == categoryid).count() != 0):
            return "Delete the advert firstly",405

        category = session.query(Category).filter(Category.id == categoryid)[0].to_dict()

        Session.query(Category).filter(Category.id == categoryid).delete()
        Session.commit()
        return "category is deleted"
    except ValidationError as err:
        return jsonify(err.messages),400
@app.route('/advertisement', methods=['DELETE'])
def delete_advert():
    args = request.args
    try:
        ad_id = args.get('ad_id')
        if  (session.query(Advertisement).filter(Advertisement.id == ad_id).count() == 0):
            return {"message": "Advert doesn't exists"}, 405
        ad = Session.query(Advertisement).filter(Advertisement.id == ad_id)[0].to_dict()

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
        if (session.query(Category).filter(Category.id == c_id).count() == 0):
            return "Category doesn't exists", 405
        ads = Session.query(Category).filter(Category.id == c_id).first()
        ad_schema=CategorySchema()
        return ad_schema.dumps(ads)
    except ValidationError as err:
        return err.messages