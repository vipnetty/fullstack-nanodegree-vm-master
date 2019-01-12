from database_setup import User, Base, Item, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

engine = create_engine('sqllite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


user1 = User(
    name='Netty',
    email='nate@gmail,com',
    picture='xxxx'
)

session.add(user1)
session.commit()

category1 = Category(
    name='Bigbang',
    user=user1
)

session.add(category1)
session.commit()

item1 = Item(
    name='Top',
    description='Smart',
    category=category1,
    user=user1
)

session.add(item1)
session.commit()

print('Success add initial information')
