import re
from flask import Flask, redirect, render_template, request, flash, session
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = "SgGwv#oW9tbam!C#9j0yhTh5P1eR6oe90zQD2$052LwdO*ez4jL0h1TiNIrVj"
mysql = MySQLConnector(app, 'logins')
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    # if registering:
    if 'reg_submit' in request.form:
        # print request.form
        # first name: letters only, at least 2 characters, was submitted
        validation = True
        if len(request.form['reg_first_name']) < 2:
            flash('First name must include at least 2 characters.', 'reg')
            validation = False
        if not request.form['reg_first_name'].isalpha():
            flash('First name may only include alphabetic characters.', 'reg')
            validation = False
        # last name: letters only, at least 2 characters, was submitted
        if len(request.form['reg_last_name']) < 2:
            flash('Last name must include at least two characters.', 'reg')
            validation = False
        if not request.form['reg_last_name'].isalpha():
            flash('Last name may only include alphabetic characters.', 'reg')
            validation = False
        # email: valid format, was submitted
        if not EMAIL_REGEX.match(request.form['reg_email']):
            flash('Please provide a valid email.', 'reg')
            validation = False
        # password: minimum 8 characters, submitted, NOT "password"
        if len(request.form['reg_password']) < 8:
            flash('Password must include no fewer than eight characters.', 'reg')
            validation = False
        if request.form['reg_password'].upper == 'PASSWORD':
            flash('Never, ever, ever, ever use "password" as your password.', 'reg')
            validation = False
        # password confirmation: matches password
        if not request.form['reg_confirm'] == request.form['reg_password']:
            flash('Password confirmation does not match password.', 'reg')
            validation = False
        # if valid: hashes+salts password using bcrypt
        if validation:
            query = ("INSERT INTO accounts (first_name, last_name, email, " +
                     "password, created_at, updated_at) VALUES " +
                     "(:first_name, :last_name, :email, :password, NOW(), NOW())")
            # print query
            data = {
                'first_name': request.form['reg_first_name'],
                'last_name': request.form['reg_last_name'],
                'email': request.form['reg_email'],
                'password': bcrypt.generate_password_hash(request.form['reg_password'])
                }
            # print data
            session['user_id'] = mysql.query_db(query, data)
            print session['user_id']
            session['user_first_name'] = request.form['reg_first_name']
            session['action'] = 'registered'
            return redirect('/success')
        # if logging in:
    elif 'log_submit' in request.form:
        # print request.form
        query = ('SELECT * FROM accounts WHERE accounts.email = ' +
                 ':log_email LIMIT 1')
        data = {
            'log_email' : request.form['log_email'],
        }
        grab_hash = mysql.query_db(query, data)
        if bcrypt.check_password_hash(grab_hash[0]['password'],
                                      request.form['log_password']):
            session['user_id'] = grab_hash[0]['id']
            print session['user_id']
            session['user_first_name'] = grab_hash[0]['first_name']
            session['action'] = 'logged in'
            return redirect('/success')
        else:
            flash('Invalid login attempt.', 'log')
    return redirect('/')

@app.route('/success')
def success():
    message = ("Hi, " + session['user_first_name'] + "! You have successfully" +
               " " + session['action'] + ".")
    return render_template('success.html', message=message)

app.run(debug=True)
