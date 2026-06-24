from database import Base
from sqlalchemy import Column, Integer, String

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    gmail = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
