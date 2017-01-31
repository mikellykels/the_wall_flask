from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app,'walldb')
app.secret_key='12345'



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def create():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    if request.form['action'] == 'register':
        if len(first_name) < 1:
            flash('First Name cannot be blank!', 'error')
            if len(first_name) < 2:
                flash('First Name must be more than 2 characters', 'error')
            if not first_name.isalpha():
                flash('First Name cannot contain numbers or special character', 'error')
            else:
                session['first_name'] = request.form['first_name']

        if len(last_name) < 1:
            flash('Last Name cannot be blank!', 'error')
            if len(last_name) < 2:
                flash('Last Name must be more than 2 characters', 'error')
            if not last_name.isalpha():
                flash('Last Name cannot contain numbers or special characters', 'error')
            else:
                session['last_name'] = request.form['last_name']

        if len(email) < 1:
            flash('Email is required', 'error')
            if not EMAIL_REGEX.match(email):
                flash('Invalid Email Address!', 'error')
            else:
                session['email'] = request.form['email']

        if len(password) < 1:
            flash('Must enter a password', 'error')
            if len(password) < 8:
                flash('Password must be more than 8 characters', 'error')
            if password != confirm_password:
                flash('Passwords do not match', 'error')
        else:
            pw_hash = bcrypt.generate_password_hash(password)
            query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at)VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
            data = {
                     'first_name': first_name,
                     'last_name': last_name,
                     'email': email,
                     'pw_hash': pw_hash
                    }
            mysql.query_db(query, data)
            return redirect('/success')
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = {
                    'email': email
                 }
    user = mysql.query_db(user_query, query_data)
    if request.form['action'] == 'login':
        if not user:
            flash("Invalid email and/or Password!", "error")
            return redirect('/')
        if bcrypt.check_password_hash(user[0]['pw_hash'], password):
            session['user_fn'] = user[0]['first_name']
            session['user_id'] = user[0]['id']
            return redirect('/wall')
        if len(password) < 1:
            flash('Must enter a password', 'error')
            if len(password) < 8:
                flash('Password must be more than 8 characters', 'error')
            return redirect('/')


@app.route('/success')
def success():
    flash('You have successfully created an account!', 'success')
    return render_template('index.html')


@app.route('/wall')
def wall():
    user_query = "SELECT * FROM users WHERE id = :id"
    user_data = {
                 'id': session['user_id']
                }
    user = mysql.query_db(user_query, user_data)

    message_query = "SELECT users.first_name, users.last_name, messages.created_at, messages.message, messages.id FROM messages LEFT JOIN users ON messages.user_id = users.id"
    messages = mysql.query_db(message_query)

    comment_query = "SELECT comments.id, comments.message_id, comments.comment, comments.created_at, users.first_name, users.last_name FROM comments LEFT JOIN users ON comments.user_id = users.id"
    comments = mysql.query_db(comment_query)
    return render_template('success.html', messages=messages, comments=comments, user=user[0])

@app.route('/message', methods=['POST'])
def message():
    query = "INSERT INTO messages (message, created_at, updated_at, user_id)VALUES (:message, NOW(), NOW(), :user_id)"
    data = {
             'message': request.form['message'],
             'user_id': session['user_id']
           }
    mysql.query_db(query, data)
    return redirect('/wall')


@app.route('/comment', methods=['POST'])
def comment():
    query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id)VALUES (:comment, NOW(), NOW(), :user_id, :message_id)"
    data = {
             'comment': request.form['comment'],
             'user_id': session['user_id'],
             'message_id': request.form['message_id']
           }
    mysql.query_db(query, data)
    return redirect('/wall')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


app.run(debug=True)
