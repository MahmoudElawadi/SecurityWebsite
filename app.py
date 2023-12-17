from flask import Flask, render_template, request, flash, session, redirect, url_for
import mysql.connector
import bcrypt
import random
import time
import pyotp
import qrcode
from flask_mail import Mail,Message
from random import randint
from flask_bcrypt import check_password_hash

def sql_connector():
    connection = mysql.connector.connect(host='localhost', user='root', password='Iloveyou1', db='security')
    cursor = connection.cursor()
    return connection, cursor

app = Flask(__name__)  # Creating an app instance
app.secret_key = "super secret key"

# mail=Mail(app)


# app.config["MAIL_SERVER"]='smtp.gmail.com'
# app.config["MAIL_PORT"]=465
# app.config["MAIL_USERNAME"]='mahmoudehab370@gmail.com'
# app.config['MAIL_PASSWORD']='Iloveyou1'                    #you have to give your password of gmail account
# app.config['MAIL_USE_TLS']=False
# app.config['MAIL_USE_SSL']=True
# otp=randint(000000,999999)

@app.route("/")  # This is a URL to the function
def index():
    return render_template("index.html")

@app.route("/gym")  # This is a URL to the function
def gym():
    return render_template("gym.html")

@app.route("/schedule")  # This is a URL to the function
def schedule():
    return render_template("schedule.html")
# @app.route("/otp")  # This is a URL to the function
# def otp():
#     return render_template("otp.html")
    
# @app.route('/otp',methods=["POST"])
# def otp():
#     email = request.form.get("email")
#     msg=Message(subject='OTP',sender='mahmoudehab370@gmail.com',recipients=[email])
#     msg.body=str(otp)
#     mail.send(msg)
#     return render_template('otp.html')


# @app.route('/validate',methods=['POST'])
# def validate():
#     user_otp=request.form.get['otp']
#     if otp==int(user_otp):
#         return "<h3>Email varification succesfull</h3>"
#     return "<h3>Please Try Again</h3>"


    
@app.route("/login", methods=["GET", "POST"])  # This is a URL to the function
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("pass")
        connection, cursor = sql_connector()
        cursor.execute("SELECT * FROM accounts WHERE username=%s", (username,))
        record = cursor.fetchone()
        print(record)
        cursor.close()
        print(record)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  
        if record[2] == 'admin':
            return render_template("admin.html")
        if record and bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                session["loggedin"] = True
                session["username"] = record[1]
                flash("Welcome back", "success")
                return redirect(url_for('gym'))
        else:
                flash("The password you entered is incorrect", "warning")
    else:
            flash("The data you entered is incorrect", "warning")

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    session.pop('password', None)
    return redirect(url_for('login'))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == 'POST':
        connection, cursor = sql_connector()
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("pass")

        # 1. Minimum length check
        if len(password) < 8:
            flash("Password must have at least 8 characters", "warning")
            return redirect(request.url)

        # 2. Character complexity check
        if not any(char.isdigit() for char in password):
            flash("Password must contain at least one digit", "warning")
            return redirect(request.url)
        if not any(char.isupper() for char in password):
            flash("Password must contain at least one uppercase letter", "warning")
            return redirect(request.url)
        if not any(char.islower() for char in password):
            flash("Password must contain at least one lowercase letter", "warning")
            return redirect(request.url)
        if not any(char in "!@#$%^&*()-_+=<>,/?." for char in password):
            flash("Password must contain at least one special character", "warning")
            return redirect(request.url)

        # 3. Username check
        cursor.execute("SELECT * FROM accounts WHERE username=%s", (username,))
        record = cursor.fetchone()
        if record:
            session["loggedin"] = True
            session["username"] = record[1]
            flash("Username already exists", "warning")
            return redirect(request.url)

        # 4. Hash and store password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO accounts (email, username, pass) VALUES (%s, %s, %s)", (email, username, hashed_password))

        connection.commit()
        connection.close()
        cursor.close()

        flash("Data inputted successfully", "success")
        return redirect(url_for('login'))

    return render_template("signup.html")


@app.route("/forget", methods=["GET", "POST"])
def forget():
    if request.method == 'POST':
        email = request.form.get("email")
        pass1 = request.form.get("pass1")
        pass2 = request.form.get("pass2")
        if len(pass1) < 8:
            flash("Password must have at least 8 characters", "warning")
            return redirect(request.url)
        connection, cursor = sql_connector()
        cursor.execute("SELECT * FROM accounts WHERE email=%s", (email,))
        record = cursor.fetchone()
        if pass1 != pass2:
            flash("Passwords do not match", "warning")
            return redirect(request.url)

        if record:
            session["email"] = record[1]
            flash("Password has been updated successfully", "success")
            cursor.execute("UPDATE accounts SET pass = %s WHERE email = %s", (bcrypt.hashpw(pass1.encode('utf-8'), bcrypt.gensalt()), email))
            connection.commit()
            connection.close()
            cursor.close()
        else:
            flash("Your account does not exist", "warning")
            return redirect(request.url)

    return render_template("forget.html")

if __name__ == "__main__":
    app.run(debug=True)  # To automatically restart the server and reflect the changes done