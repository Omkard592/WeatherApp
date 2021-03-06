# Omkar Deshmukh

# Imports
from flask import Flask, render_template, flash, redirect, url_for, request, session, logging
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import requests
import json
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Config PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/weatherapp_users'
#app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///user.db')

# DB object
db = SQLAlchemy(app)

# User model
class User(db.Model):
    name = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    cities = db.Column(db.String())
    curr_city = db.Column(db.String())

    def __init__(self, name, username, email, password, cities, curr_city):
        self.name = name
        self.username = username
        self.email = email
        self.password = password
        self.cities = cities

# Guard to protect pages
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Home
@app.route('/')
def index():
    return render_template('home.html')

# Profile
@app.route('/profile')
@is_logged_in
def profile():
    myUser = User.query.filter_by(username = session['username']).first()
    if myUser.cities is not None:
        myUser.cities = sorted(myUser.cities)
    return render_template('profile.html', myuser = myUser)

# Registration form
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
    validators.DataRequired(),
    validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')

# Register user
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        cities = None
        curr_city = ""

        new_user = User(name, username, email, password, cities, curr_city)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Your are now registered and can log in', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            flash('User already exists!', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_candidate = request.form['username']
        pwd_candidate = request.form['password']

        myUser = User.query.filter_by(username = username_candidate).first()
        #app.logger.info(myUser)

        if myUser is not None:
            pwd = myUser.password

            if sha256_crypt.verify(pwd_candidate, pwd):
                session['logged_in'] = True
                session['username'] = myUser.username
                session['cities'] = myUser.cities
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard', myuser = myUser))
            else:
                error = 'Invalid credentials'
                return render_template('login.html', error = error)
        else:
            error = 'Username not found'
            return render_template('login.html', error = error)
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Your are now logged out', 'success')
    return redirect(url_for('login'))

def getUser():
    myUser = User.query.filter_by(username = session['username']).first()
    return myUser
app.jinja_env.globals.update(getUser=getUser)

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    myUser = User.query.filter_by(username = session['username']).first()
    # Current city is set and city list is not empty
    if myUser.cities is not None and myUser.curr_city:
        myUser.cities = sorted(myUser.cities)
        c_ele = [x.strip() for x in ''.join(myUser.curr_city).split(',')]
        citydata = requests.get('http://api.wunderground.com/api/87ce814483be97e9/alerts/forecast/conditions/q/'+c_ele[1]+'/'+c_ele[0]+'.json')
        myUser.xx = json.loads(citydata.text)
        # Found weather details for that exact city
        if 'current_observation' in myUser.xx:
            myUser.alerts = myUser.xx["alerts"]
            myUser.forecast = myUser.xx["forecast"]
            myUser.xx = myUser.xx["current_observation"]

        # Found multiple cities of the same name
        else:
            zmw = ""
            # Extract country and then call the API again using the zmw field with unique values for every city
            if 'results' in myUser.xx["response"]:
                for r in myUser.xx["response"]["results"]:
                    if(myUser.curr_city.find(r["country_name"]) != -1):
                        zmw = r["zmw"]
                citydata = requests.get('http://api.wunderground.com/api/87ce814483be97e9/alerts/forecast/conditions/q/zmw:'+zmw+'.json')
                myUser.xx = json.loads(citydata.text)
                # No details found for this city after using zmw field
                if 'current_observation' not in myUser.xx:
                    flash('No details found for this city', 'danger')
                    return redirect(url_for('dashboard'))
                myUser.alerts = myUser.xx["alerts"]
                myUser.forecast = myUser.xx["forecast"]
                myUser.xx = myUser.xx["current_observation"]
            # No details exist for this city (Weather API is missing it's data)
            else:
                flash('No details found for this city', 'danger')
                return redirect(url_for('dashboard'))
    return render_template('dashboard.html', myuser = myUser)

# Change current city
@app.route('/change_curr_city/<string:cc>', methods=['POST'])
@is_logged_in
def change_curr_city(cc):
    chngUser = User.query.filter_by(username = session['username']).first()
    chngUser.curr_city = cc
    db.session.commit()
    return redirect(url_for('dashboard', myuser = chngUser))

# Add d city
@app.route('/add_city', methods=['POST'])
@is_logged_in
def add_city():
    chngUser = User.query.filter_by(username = session['username']).first()
    newcity = request.form['hiddenlabel']
    session['cities'] = chngUser.cities
    if newcity != '':
        result = [newcity]
        if chngUser.cities is not None:
            if newcity not in chngUser.cities:
                for c in chngUser.cities:
                    result.append(c)
                chngUser.cities = result
        else:
            chngUser.cities = result
        db.session.commit()
        session['cities'] = result
    return redirect(url_for('get_search'))

# Delete a city
@app.route('/delete_city/<string:dc>', methods=['POST'])
@is_logged_in
def delete_city(dc):
    delUser = User.query.filter_by(username = session['username']).first()
    # Direct list manipulation was does not work when modifying the list, hence the manual looping
    result = []
    for char in delUser.cities:
        if char != dc:
            result.append(char)
    delUser.cities = result
    session['cities'] = result
    if delUser.curr_city == dc:
        delUser.curr_city = ''
    db.session.commit()
    return redirect(url_for('profile', myuser=delUser))

# Search a city
@app.route('/templates/includes/_search.html')
@is_logged_in
def get_search():
    return render_template('includes/_search.html')

if __name__ == '__main__':
    db.create_all()
    app.secret_key = 'not_really_a_good_secret'
    app.run(debug=True)
