from database_setup import User, Base, Item, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

engine = create_engine('sqlite:///catalog.db',
                       connect_args={'check_same_thread': False})


Session = sessionmaker(bind=engine)


session = Session()

user1 = User(
    name='Netty',
    email='nate@gmail.com',
    picture=''
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
    name='TOP',
    description='Wow',
    category=category1,
    user=user1
)

session.add(item1)
session.commit()

print('Success add initial information')
