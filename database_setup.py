from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
# creates foreign key relationships
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

# establish classes as sqlalchemy classes corresponding to DB tables
Base = declarative_base()


# classes
class user(Base):

    __tablename__ = 'user'

    userID = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    email = Column(String(80), nullable = False)
    picture = Column(String(250))
    # starcount =  Column(Integer, ForeignKey=??) insert aggregate function?


class domain(Base):

    __tablename__ = 'domain'

    domID = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    userID = Column(Integer, ForeignKey('user.userID'))
    pullUser = relationship(user)

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'name': self.name,
            'id': self.domID,
        }


class event(Base):

    __tablename__ = 'events'

    eventID = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    category = Column(String(250))
    description = Column(String(250))
    thumbnail_url = Column(String(255))
    stars = Column(Integer, nullable = False)
    domID = Column(Integer, ForeignKey('domain.domID'))
    dom = relationship(domain)
    userID = Column(Integer, ForeignKey('user.userID'))
    pullUser = relationship(user)

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.eventID,
            'stars': self.stars,
            'category': self.category
        }


# Configure and initialize sqlite engine for P3
# engine = create_engine('sqlite:///goldstarswithusers.db')
# for P5
engine = create_engine('postgresql://catalog:catalog@localhost/catalog')

# goes into DB and adds classes as new tables to DB
Base.metadata.create_all(engine)
