from unittest.mock import ANY
from models import Session, Base, engine, User, Advertisement, Category
from app import app
from werkzeug.security import generate_password_hash
from flask_testing import TestCase


class MyUser(TestCase):
    def setUp(self):
        app.config['SECURITY_KEY'] = '1'
        super().setUp()
        self.user_1_data = {
            "username": "user1",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1@gmail.com",
            "phone_number": "0680592458",
            "password": "11111111"
        }

        self.user_1_data_hashed = {
            "id": ANY,
            "username": "user1",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1@gmail.com",
            "phone_number": "0680592458",
            "password": ANY
        }

        self.user_2_data = {
            "username": "user1",
            "first_name": "olenka",
            "last_name": "pyrih",
            "address": "Lviv",
            "email": "user2@gmail.com",
            "phone_number": "096105985",
            "password": "8569511"
        }

        self.user_3_data = {
            "username": "user3",
            "firstname": "3",
            "last_name": "user",
            "password": "password"
        }

        self.user_4_data = {
            "username": "user4",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user4@gmail.com",
            "phone_number": "068055492458",
            "password": "11111111"
        }

        self.user_4_data_hashed = {
            "id": ANY,
            "username": "user4",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user4@gmail.com",
            "phone_number": "068055492458",
            "password": ANY
        }

        self.user_1_to_update = {
            "username": "olenka_p",
            "first_name": "qwerty",
            "last_name": "pyrih",
        }

        self.user_to_delete = {
            "username": "userdel",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "userdel@gmail.com",
            "phone_number": "06805252458",
            "password": "11111111"
        }

        self.user_to_delete_hashed = {
            "id": ANY,
            "username": "userdel",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "userdel@gmail.com",
            "phone_number": "06805252458",
            "password": ANY
        }
        self.user_1_to_update_hashed = {
            "id": ANY,
            "username": "olenka_p",
            "first_name": "qwerty",
            "last_name": "pyrih",
            "address": "Lviv",
            "email": "user1@gmail.com",
            "phone_number": "0680592458",
            "password": ANY
        }

        self.user_to_update = {
            "username": "userup",
            "first_name": "qwerty",
            "last_name": "pyrih",
            "address": "Lviv",
            "email": "userup@gmail.com",
            "phone_number": "068892458",
            "password": "userup"
        }

        self.user_to_update_hashed = {
            "id": ANY,
            "username": "userup",
            "first_name": "qwerty",
            "last_name": "pyrih",
            "address": "Lviv",
            "email": "userup@gmail.com",
            "phone_number": "068892458",
            "password": ANY
        }

        self.updation = {
            "username": "user4"
        }

        self.session = Session()

    def create_app(self):
        return app

    def close_session(self):
        self.session.close()

    def tearDown(self):
        self.close_session()


class MyCategory(TestCase):
    def setUp(self):
        app.config['SECURITY_KEY'] = '1'
        super().setUp()

        self.user_1_data = {
            "username": "user1cat",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1cat@gmail.com",
            "phone_number": "0592458",
            "password": "11111111"
        }

        self.user_1_data_hashed = {
            "id": ANY,
            "username": "user1cat",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1cat@gmail.com",
            "phone_number": "0592458",
            "password": ANY
        }
        self.category_1_data = {
            "name": "missing pet"
        }

        self.category_1_data_resp = {
            "id": ANY,
            "name": "missing pet"
        }
        self.session = Session()

    def create_app(self):
        return app

    def close_session(self):
        self.session.close()

    def tearDown(self):
        self.close_session()


class MyAdvertisement(TestCase):
    def setUp(self):
        app.config['SECURITY_KEY'] = '1'
        super().setUp()
        self.user_1_data = {
            "username": "user1adv",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1adv@gmail.com",
            "phone_number": "0592458",
            "password": "11111111"
        }

        self.user_1_data_hashed = {
            "id": ANY,
            "username": "user1adv",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1adv@gmail.com",
            "phone_number": "0592458",
            "password": ANY
        }

        self.user_2_data = {
            "username": "user1adv2",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1adv2@gmail.com",
            "phone_number": "059245985268",
            "password": "11111111"
        }

        self.user_2_data_hashed = {
            "id": ANY,
            "username": "user1adv2",
            "first_name": "aaa",
            "last_name": "bbb",
            "address": "Lviv",
            "email": "user1adv2@gmail.com",
            "phone_number": "059245985268",
            "password": ANY
        }

        self.category_1_data = {
            "name": "buy smth"
        }

        self.category_1_data_resp = {
            "id": ANY,
            "name": "buy smth"
        }

        self.advertisement_1_data = {
            "description": "Buy a new phone",
            "status": 0
        }

        self.advertisement_1_data_resp = {
            "id": ANY,
            "description": "Buy a new phone",
            "status": 0,
            "user_id": ANY,
            "category_id": ANY
        }

        self.advertisement_2_data = {
            "description": "Laptop",
            "status": 1
        }

        self.advertisement_2_data_resp = {
            "id": ANY,
            "description": "Laptop",
            "status": 1,
            "user_id": ANY,
            "category_id": ANY
        }

        self.advertisement_to_update = {
            "description": "Laptopssss",
            "status": 1
        }

        self.advertisement_to_update_resp = {
            "id": ANY,
            "description": "Laptopssss",
            "status": 1,
            "user_id": ANY,
            "category_id": ANY
        }

        self.update_with = {
            "description": "No more laptops"
        }
        self.session = Session()

    def create_app(self):
        return app

    def close_session(self):
        self.session.close()

    def tearDown(self):
        self.close_session()


class UserTest(MyUser):
    def test01_new_user(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, {
            "id": ANY,
            "username": self.user_1_data_hashed['username'],
            "first_name": self.user_1_data_hashed['first_name'],
            "last_name": self.user_1_data_hashed['last_name'],
            "address": self.user_1_data_hashed['address'],
            "email": self.user_1_data_hashed['email'],
            "phone_number": self.user_1_data_hashed['phone_number'],
            "password": ANY
        })

    def test01_user_to_del(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_to_delete
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, {
            "id": ANY,
            "username": self.user_to_delete_hashed['username'],
            "first_name": self.user_to_delete_hashed['first_name'],
            "last_name": self.user_to_delete_hashed['last_name'],
            "address": self.user_to_delete_hashed['address'],
            "email": self.user_to_delete_hashed['email'],
            "phone_number": self.user_to_delete_hashed['phone_number'],
            "password": ANY
        })

    def test01_user_to_update(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_to_update
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, {
            "id": ANY,
            "username": self.user_to_update_hashed['username'],
            "first_name": self.user_to_update_hashed['first_name'],
            "last_name": self.user_to_update_hashed['last_name'],
            "address": self.user_to_update_hashed['address'],
            "email": self.user_to_update_hashed['email'],
            "phone_number": self.user_to_update_hashed['phone_number'],
            "password": ANY
        })

    def test001_new_user(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_4_data
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, {
            "id": ANY,
            "username": self.user_4_data_hashed['username'],
            "first_name": self.user_4_data_hashed['first_name'],
            "last_name": self.user_4_data_hashed['last_name'],
            "address": self.user_4_data_hashed['address'],
            "email": self.user_4_data_hashed['email'],
            "phone_number": self.user_4_data_hashed['phone_number'],
            "password": ANY
        })

    def test02_fail_new_user(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        self.assertEqual(resp.status_code, 422)

    def test03_fail_new_user(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_3_data
        )
        self.assertEqual(resp.status_code, 422)

    def test04_fail_new_user(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_2_data
        )
        self.assertEqual(resp.status_code, 422)

    def test05_find_user_by_username(self):
        user1 = self.session.query(User).filter(User.username == self.user_1_data['username']).one()
        resp = self.client.get(
            "/user/username?{}={}".format("user_username", user1.username),
            auth=(self.user_1_data['username'], self.user_1_data['password']),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.user_1_data_hashed)

    def test050_find_user_by_username(self):
        resp = self.client.get(
            "/user/username?{}={}".format("user_username", "gaffgye"),
            auth=(self.user_1_data['username'], self.user_1_data['password']),
        )
        self.assertEqual(resp.status_code, 405)

    def test06_update_user(self):
        user = self.session.query(User).filter(User.username == self.user_1_data['username']).first()
        resp = self.client.put(
            "/user/username?{}={}".format("user_id", user.id),
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.user_1_to_update
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.user_1_to_update_hashed)

    def test07_fail_update_user(self):
        resp = self.client.put(
            "/user/username?{}={}".format("user_id", 999),
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.user_1_to_update
        )
        self.assertEqual(resp.status_code, 401)

    def test080_fail_update_user(self):
        user = self.session.query(User).filter(User.username == self.user_to_update['username']).first()
        resp = self.client.put(
            "/user/username?{}={}".format("user_id", user.id),
            auth=(self.user_4_data['username'], self.user_4_data['password']),
            json=self.user_to_update
        )
        self.assertEqual(resp.status_code, 403)

    def test0800_fail_update_user(self):
        user = self.session.query(User).filter(User.username == self.user_to_update['username']).first()
        resp = self.client.put(
            "/user/username?{}={}".format("user_id", user.id),
            auth=(self.user_to_update['username'], self.user_to_update['password']),
            json=self.updation
        )
        self.assertEqual(resp.status_code, 400)

    def test08_delete_user(self):
        resp = self.client.delete(
            "/user/username?{}={}".format("user_id", 99999),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 401)

    def test09_delete_user(self):
        user = self.session.query(User).filter(User.username == self.user_4_data['username']).one()
        resp = self.client.delete(
            "/user/username?{}={}".format("user_id", user.id),
            auth=(self.user_to_delete['username'], self.user_to_delete['password'])
        )
        self.assertEqual(resp.status_code, 403)

    def test10_delete_user(self):
        user = self.session.query(User).filter(User.username == self.user_to_delete['username']).first()
        resp = self.client.delete(
            "/user/username?{}={}".format("user_id", user.id),
            auth=(self.user_to_delete['username'], self.user_to_delete['password'])
        )
        self.assertEqual(resp.status_code, 200)


class CategoryTest(MyCategory):
    def test11_fail_new_category(self):
        resp = self.client.post(
            "/category",
            # auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.category_1_data
        )
        self.assertEqual(resp.status_code, 401)
        # self.assertEqual(resp.json, self.category_1_data_resp)

    def test11_new_category(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        resp = self.client.post(
            "/category",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.category_1_data
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.category_1_data_resp)

    def test12_fail_find_category_by_id(self):
        resp = self.client.get(
            "/category?{}={}".format("c_id", 8888),
        )
        self.assertEqual(resp.status_code, 405)

    def test14_find_category_by_id(self):
        category = self.session.query(Category).filter(Category.name == self.category_1_data['name']).first()
        resp = self.client.get(
            "/category?{}={}".format("c_id", category.id),
        )
        self.assertEqual(resp.status_code, 200)

    def test14_fail_delete_category_by_id(self):
        category = self.session.query(Category).filter(Category.name == self.category_1_data['name']).first()
        resp = self.client.delete(
            "/category?{}={}".format("category_id", category.id))
        self.assertEqual(resp.status_code, 401)

    def test15_fail_delete_category_by_id(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        category = self.session.query(Category).filter(Category.name == self.category_1_data['name']).first()
        resp = self.client.delete(
            "/categy?{}={}".format("category_id", category.id),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 404)

    def test14_delete_category_by_id(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        resp = self.client.delete(
            "/category?{}={}".format("category_id", -2),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 405)

    def test15_success_delete_category_by_id(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        category = self.session.query(Category).filter(Category.name == self.category_1_data['name']).first()
        resp = self.client.delete(
            "/category?{}={}".format("category_id", category.id),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)


class TestAdvertisement(MyAdvertisement):
    def test20_fail_new_advertisement(self):
        resp = self.client.post(
            "/advertisement",
            json=self.advertisement_1_data
        )
        self.assertEqual(resp.status_code, 401)

    def test21_fail_new_advertisement(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        user = self.session.query(User).filter(User.username == self.user_1_data['username']).first()
        category = self.session.query(Category).filter(Category.name == self.category_1_data["name"]).first()
        self.advertisement_1_data_resp["category_id"] = "555555"
        self.advertisement_1_data_resp["user_id"] = user.id

        resp = self.client.post(
            "/advertisement",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.advertisement_1_data
        )
        self.assertEqual(resp.status_code, 405)

    def test21_new_advertisement(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        resp = self.client.post(
            "/category",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.category_1_data
        )
        user = self.session.query(User).filter(User.username == self.user_1_data['username']).first()
        category = self.session.query(Category).filter(Category.name == self.category_1_data["name"]).first()
        self.advertisement_1_data["category_id"] = category.id
        self.advertisement_1_data["user_id"] = user.id
        resp = self.client.post(
            "/advertisement",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.advertisement_1_data
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.advertisement_1_data_resp)

    def test21_1new_advertisement(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_1_data
        )
        resp = self.client.post(
            "/category",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.category_1_data
        )
        user = self.session.query(User).filter(User.username == self.user_1_data['username']).first()
        category = self.session.query(Category).filter(Category.name == self.category_1_data["name"]).first()
        self.advertisement_2_data["category_id"] = category.id
        self.advertisement_2_data["user_id"] = user.id
        resp = self.client.post(
            "/advertisement",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.advertisement_2_data
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.advertisement_2_data_resp)

    def test21_2new_advertisement(self):
        user = self.session.query(User).filter(User.username == self.user_1_data['username']).first()
        category = self.session.query(Category).filter(Category.name == self.category_1_data["name"]).first()
        self.advertisement_to_update["category_id"] = category.id
        self.advertisement_to_update["user_id"] = user.id
        resp = self.client.post(
            "/advertisement",
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.advertisement_to_update
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.advertisement_to_update_resp)

    def test21_3new_advertisement(self):
        resp = self.client.post(
            "/user/register",
            json=self.user_2_data
        )
        user = self.session.query(User).filter(User.username == self.user_2_data['username']).first()
        category = self.session.query(Category).filter(Category.name == self.category_1_data["name"]).first()
        self.advertisement_2_data["category_id"] = category.id
        self.advertisement_2_data["user_id"] = user.id
        resp = self.client.post(
            "/advertisement",
            auth=(self.user_2_data['username'], self.user_2_data['password']),
            json=self.advertisement_2_data
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json, self.advertisement_2_data_resp)

    def test22_find_advertisement_by_id(self):
        advert = self.session.query(Advertisement).filter(Advertisement.description == self.advertisement_1_data['description']).first()
        resp = self.client.get(
            "/advertisement?{}={}".format("advert_id", advert.id),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)

    def test23_fail_find_advertisement_by_access(self):
        advert = self.session.query(Advertisement).filter(Advertisement.description == self.advertisement_1_data['description']).first()
        resp = self.client.get(
            "/advertisement/findByAccess?{}={}".format("advert_access", int(advert.status)),
        )
        self.assertEqual(resp.status_code, 403)

    def test23_find_advertisement_by_access(self):
        advert = self.session.query(Advertisement).filter(Advertisement.description == self.advertisement_1_data['description']).first()
        resp = self.client.get(
            "/advertisement/findByAccess?{}={}".format("advert_access", int(advert.status)),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)

    def test23_1find_advertisement_by_access(self):
        advert = self.session.query(Advertisement).filter(Advertisement.description == self.advertisement_2_data['description']).first()
        resp = self.client.get(
            "/advertisement/findByAccess?{}={}".format("advert_access", int(advert.status)),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)

    def test24_fail_find_advertisement_by_category(self):
        resp = self.client.get(
            "/advertisement/findByCategory?{}={}".format("advert_category", "dfghjmk"),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 400)

    def test24_find_advertisement_by_category(self):
        category = self.session.query(Category).filter(Category.name == self.category_1_data['name']).first()
        resp = self.client.get(
            "/advertisement/findByCategory?{}={}".format("advert_category", category.name),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)

    def test25_find_advertisement_by_user(self):
        user = self.session.query(User).filter(User.username == self.user_1_data['username']).first()
        resp = self.client.get(
            "/advertisement/findByUser?{}={}".format("advert_user", user.username),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)

    def test25_fail_find_advertisement_by_user(self):
        resp = self.client.get(
            "/advertisement/findByUser?{}={}".format("advert_user", "user.username"),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 400)

    def test26_fail_update_advertisement(self):
        advert = self.session.query(Advertisement).filter(Advertisement.description == self.advertisement_to_update['description']).first()
        resp = self.client.put(
            "/advertisement?{}={}".format("ad_id", advert.id),
            auth=(self.user_1_data['username'], self.user_1_data['password']),
            json=self.update_with
        )
        self.assertEqual(resp.status_code, 404)

    def test27_2fail_delete_advert(self):
        resp = self.client.delete(
            "/advertisement?{}={}".format("ad_id", 64548465),
            auth=(self.user_2_data['username'], self.user_2_data['password'])
        )
        self.assertEqual(resp.status_code, 405)

    def test27_success_delete_advert(self):
        advert = self.session.query(Advertisement).filter(Advertisement.description == self.advertisement_1_data['description']).first()
        resp = self.client.delete(
            "/advertisement?{}={}".format("ad_id", advert.id),
            auth=(self.user_1_data['username'], self.user_1_data['password'])
        )
        self.assertEqual(resp.status_code, 200)










