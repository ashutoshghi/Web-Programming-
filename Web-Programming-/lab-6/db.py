from sqlalchemy import MetaData, create_engine
from databases import Database

Database_URL = "sqlite:///./test.db"
database = Database(Database_URL)
metadata = MetaData()
engine = create_engine(Database_URL)
