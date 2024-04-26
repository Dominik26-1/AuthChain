from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import Config

Base = declarative_base()
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)

Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)

session = Session()
