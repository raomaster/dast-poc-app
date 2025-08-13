from sqlalchemy import Column,Integer,String,ForeignKey,Text
from sqlalchemy.orm import relationship
from .db import Base
class User(Base):
    __tablename__='users'
    id=Column(Integer,primary_key=True,index=True)
    username=Column(String(50),unique=True,index=True,nullable=False)
    password_hash=Column(String(128),nullable=False)
    notes=relationship('Note',back_populates='owner',cascade='all,delete')
class Note(Base):
    __tablename__='notes'
    id=Column(Integer,primary_key=True,index=True)
    owner_id=Column(Integer,ForeignKey('users.id'),nullable=False)
    content=Column(Text,nullable=False)
    owner=relationship('User',back_populates='notes')
