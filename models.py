from uuid import UUID
from flask import jsonify
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session
from marshmallow import Schema, fields, validate, ValidationError
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
import sys

source = open("connect_string.txt", "r")
engine = create_engine(source.readline())
#engine = create_engine('mysql+pymysql://root:root1234@localhost:3306/advert')
SessionFactory = sessionmaker(bind=engine)
Session = scoped_session(SessionFactory)
Base = declarative_base()
session = Session()


class CustomSerializerMixin(SerializerMixin):
	serialize_types = (
		(UUID, lambda x: str(x)),
	)


def validate_email(email):
	if "@" not in email:
		return False
	return True


def validate_phone(phone_number):
	temp = 0
	for i in phone_number:
		if i.isalpha():
			temp += 1
	if temp > 0 or len(phone_number) < 1 or len(phone_number) > 13:
		return False
	return True


def validate_entry_id(entry, entry_id):
	if Session.query(entry).filter(entry.id == entry_id).count() == 0:
		return False
	return True


def validate_username(username1):
	if not (session.query(User).filter(User.username == username1).count() == 0):
		raise ValidationError("Username exists")
	if len(username1) < 1 or len(username1) > 20:
		raise ValidationError("Incorect length")


class User(Base, CustomSerializerMixin):
	__tablename__ = 'user'
	serialize_only = {'id', 'username', 'first_name', 'last_name', 'address', 'email', 'phone_number'}
	id = Column('id', Integer, primary_key=True)
	username = Column('username', String(20), nullable=False)
	first_name = Column('first_name', String(15), nullable=False)
	last_name = Column('last_name', String(15), nullable=False)
	password = Column('password', String(250), nullable=False)
	address = Column('address', String(60), nullable=False)
	email = Column('email', String(45), nullable=False)
	phone_number = Column('phone_number', String(13), nullable=False)


class UserSchema(SQLAlchemyAutoSchema):
	class Meta:
		model = User
		# include_relationships = True
		load_instance = True
		include_fk = True

	first_name = fields.String(validate=validate.Length(min=1, max=15))
	last_name = fields.String(validate=validate.Length(min=1, max=15))
	email = fields.String(validate=validate.Email())
	address = fields.String(validate=validate.Length(min=1, max=60))
	phone_number = fields.String(validate=validate_phone)
	username = fields.String(validate=validate_username)
	password = fields.String(validate=validate.Length(min=1, max=250))


class Category(Base, CustomSerializerMixin):
	__tablename__ = 'category'
	serialize_only = {'id', 'name'}
	id = Column('id', Integer, primary_key=True, autoincrement=True)
	name = Column('name', String(45), nullable=False)


class CategorySchema(SQLAlchemyAutoSchema):
	class Meta:
		model = Category
		# include_relationships = True
		load_instance = True
		include_fk = True

	name = fields.String(validate=validate.Length(min=1, max=45))


class Advertisement(Base, CustomSerializerMixin):
	__tablename__ = 'advertisement'
	serialize_only = {'id', 'description', 'status', 'user_id', 'category_id'}
	id = Column('id', Integer, primary_key=True, autoincrement=True)
	description = Column('description', String(100), nullable=False)
	status = Column('status', Boolean, nullable=False)
	user_id = Column('user_id', Integer, ForeignKey(User.id))
	category_id = Column('category_id', Integer, ForeignKey(Category.id))
	category = relationship(Category, backref='advertisement', lazy='joined')
	user = relationship(User, backref='advertisement', lazy='joined')


class AdvertSchema(SQLAlchemyAutoSchema):
	class Meta:
		model = Advertisement
		# include_relationships = True
		load_instance = True

	# include_fk = True

	description = fields.String(validate=validate.Length(min=1, max=100))
	status = fields.Boolean()
	user_id = fields.Integer()
	category_id = fields.Integer()
