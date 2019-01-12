#!/usr/bin/env python
from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from pprint import pprint
import httplib2
import random
import string
import json
import requests
app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db',
                       connect_args={'check_same_thread': False})
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


# Connect to the Google Sign-in oAuth method.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Get user info.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if the user exists. If it doesn't, make a new one.
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    # Show a welcome screen upon successful login.
    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; '
    output += 'border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in : %s" % login_session['username'])
    print("Success")
    return output


# Disconnect Google Account
def gdisconnect():
    # Only disconnect the connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Log out user
@app.route('/logout')
def logout():
    if 'username' in login_session:
        gdisconnect()
        del login_session['google_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have successfully logged out")
        return redirect(url_for('home'))
    else:
        flash("You are not logged in. Please log in and try again.")
        return redirect(url_for('home'))


# Create new user
def create_user(login_session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# Show all categories and items
@app.route('/')
@app.route('/catalog/')
@app.route('/catalog/items/')
def home():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template(
        'index.html', categories=categories, items=items)


# Add new category
@app.route("/catalog/category/new/", methods=['GET', 'POST'])
def add_category():
    if 'username' not in login_session:
        flash("Please log in to application.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        if request.form['add-category-name'] == '':
            flash('Please fill information category.')
            return redirect(url_for('home'))
        category = session.query(Category).\
            filter_by(name=request.form['add-category-name']).first()
        if category is not None:
            flash('Category already exists.')
            return redirect(url_for('add_category'))
        new_category = Category(
            name=request.form['add-category-name'],
            user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash('New category %s successful add' % new_category.name)
        return redirect(url_for('home'))
    else:
        return render_template('add-category.html')


# Add new item
@app.route("/catalog/item/new/", methods=['GET', 'POST'])
def add_item():
    if 'username' not in login_session:
        flash("Please log in.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        item = session.query(Item).filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The entered item already exists.')
                return redirect(url_for("add_item"))
        new_item = Item(
            name=request.form['name'],
            category_id=request.form['category'],
            description=request.form['description'],
            user_id=login_session['user_id']
        )
        session.add(new_item)
        session.commit()
        flash('New item successful add')
        return redirect(url_for('home'))
    else:
        items = session.query(Item).\
            filter_by(user_id=login_session['user_id']).all()
        categories = session.query(Category).\
            filter_by(user_id=login_session['user_id']).all()
        return render_template(
            'add-item.html',
            items=items,
            categories=categories
        )


# Add new item by category id
@app.route("/catalog/category/<int:category_id>/item/new/",
           methods=['GET', 'POST'])
def add_item_by_category(category_id):
    if 'username' not in login_session:
        flash("You are not authorised to access this page")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        item = session.query(Item).filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The item already exists.')
                return redirect(url_for("add_item"))
        new_item = Item(
            name=request.form['name'],
            user_id=login_session['user_id'],
            category_id=category_id,
            description=request.form['description'])
        session.add(new_item)
        session.commit()
        flash('New item successful Add.')
        return redirect(url_for('show_items_in_category',
                                category_id=category_id))
    else:
        category = session.query(Category).filter_by(id=category_id).first()
        return render_template('add-item-cate.html', category=category)


# Check item in database
def exists_item(item_id):
    item = session.query(Item).filter_by(id=item_id).first()
    if item is not None:
        return True
    else:
        return False


# Check category in database
def exists_category(category_id):
    category = session.query(Category).filter_by(id=category_id).first()
    if category is not None:
        return True
    else:
        return False


# Show item by id
@app.route('/catalog/item/<int:item_id>/')
def show_item(item_id):
    if exists_item(item_id):
        item = session.query(Item).filter_by(id=item_id).first()
        category = session.query(Category)\
            .filter_by(id=item.category_id).first()
        owner = session.query(User).filter_by(id=item.user_id).first()
        return render_template(
            "item.html",
            item=item,
            category=category,
            owner=owner
        )
    else:
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))


# Edit item
@app.route("/catalog/item/<int:item_id>/edit/", methods=['GET', 'POST'])
def edit_item(item_id):
    if 'username' not in login_session:
        flash("Please log in.")
        return redirect(url_for('login'))

    if not exists_item(item_id):
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    item = session.query(Item).filter_by(id=item_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You are not authorised to access this page.")
        return redirect(url_for('home'))
    if request.method == 'POST':
        if request.form['category']:
            item.category_id = request.form['category']
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('Item successful updated')
        return redirect(url_for('edit_item', item_id=item_id))
    else:
        categories = session.query(Category).\
            filter_by(user_id=login_session['user_id']).all()
        return render_template(
            'edit-item.html',
            item=item,
            categories=categories
        )


# Delete item
@app.route("/catalog/item/<int:item_id>/delete/", methods=['GET', 'POST'])
def delete_item(item_id):
    if 'username' not in login_session:
        flash("Please log in.")
        return redirect(url_for('login'))
    if not exists_item(item_id):
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    item = session.query(Item).filter_by(id=item_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You are not authorised to access this page.")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Item successful deleted")
        return redirect(url_for('home'))
    else:
        return render_template('delete-item.html', item=item)


# Show items in category
@app.route('/catalog/category/<int:category_id>/items/')
def show_items_in_category(category_id):
    if not exists_category(category_id):
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    category = session.query(Category).filter_by(id=category_id).first()
    items = session.query(Item).filter_by(category_id=category.id).all()
    total = session.query(Item).filter_by(category_id=category.id).count()
    return render_template(
        'items.html',
        category=category,
        items=items,
        total=total)


# Edit category
@app.route('/catalog/category/<int:category_id>/edit/',
           methods=['GET', 'POST'])
def edit_category(category_id):
    category = session.query(Category).filter_by(id=category_id).first()
    if 'username' not in login_session:
        flash("Please log in.")
        return redirect(url_for('login'))
    if not exists_category(category_id):
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    if login_session['user_id'] != category.user_id:
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            session.add(category)
            session.commit()
            flash('Category successful updated')
            return redirect(url_for('show_items_in_category',
                                    category_id=category.id))
    else:
        return render_template('edit-category.html', category=category)


# Delete category
@app.route('/catalog/category/<int:category_id>/delete/',
           methods=['GET', 'POST'])
def delete_category(category_id):
    category = session.query(Category).filter_by(id=category_id).first()
    if 'username' not in login_session:
        flash("Please log in.")
        return redirect(url_for('login'))
    if not exists_category(category_id):
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    if login_session['user_id'] != category.user_id:
        flash("Sorry, we are not able to process your request.")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category successful deleted")
        return redirect(url_for('home'))
    else:
        return render_template("delete-category.html", category=category)


# JSON Endpoints
@app.route('/catalog.json')
def catalog_json():
    items = session.query(Item).order_by(Item.id.asc())
    return jsonify(catalog=[i.serialize for i in items])


# Return JSON of item in category
@app.route(
    '/categories/<int:category_id>/item/<int:item_id>/JSON')
def catalog_item_json(category_id, item_id):
    item = session.query(Item).\
        filter_by(id=item_id, category_id=category_id).one()
    return jsonify(item=item.serialize)


# JSON of all categories information
@app.route('/categories/JSON')
def categories_json():
    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])


if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host="0.0.0.0", port=8000, debug=True)
