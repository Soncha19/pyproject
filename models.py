

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session

engine = create_engine('mysql+pymysql://root:root1234@localhost:3306/advert')
SessionFactory = sessionmaker(bind=engine)
Session = scoped_session(SessionFactory)
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column('id', Integer, primary_key=True)
    username = Column('username', String(20), nullable=False)
    first_name = Column('first_name', String(15), nullable=False)
    last_name = Column('last_name', String(15), nullable=False)
    address = Column('address', String(60), nullable=False)
    email = Column('email', String(45), nullable=False)
    phone_number = Column('phone_number', String(13), nullable=False)


class Category(Base):
    __tablename__ = 'category'
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    name = Column('name', String(45), nullable=False)


class Advertisement(Base):
    __tablename__ = 'advertisement'
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    description = Column('description', String(100), nullable=False)
    status = Column('status', Boolean, nullable=False)
    user_id = Column('user_id', Integer, ForeignKey(User.id))
    category_id = Column('category_id', Integer, ForeignKey(Category.id))
    category = relationship(Category, backref='advertisement', lazy='joined')
    user = relationship(User, backref='advertisement', lazy='joined')
