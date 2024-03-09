"""Angelo Barcelona SDEV 300, lab6"""
import csv
import os
import logging
import datetime as dt
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from passlib.hash import sha256_crypt

app = Flask(__name__)
PASSWORD_FILE = 'userdata.txt'
COMMON_PW_FILE = 'CommonPassword.txt'

logging.basicConfig(filename='applog.log', level=logging.DEBUG,
                    format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')


@app.route('/')
def homepage():
    """returns home page login screen"""
    return render_template("login.html")


@app.before_request
def before_request():
    """Checks user is in session, grabs user IP address of any request
    and user name.  Name and User IP are logged"""
    g.user = None
    if 'user' in session:
        g.user = session['user']
        ip_addr = request.remote_addr
        logging.info(f"User being logged: {g.user} \n\t\t\t\t\t User IP: {ip_addr}")


@app.route('/logout')
def logout():
    """passes Logout flash message"""
    flash("You have been logged out.", "info")
    session.pop('user', None)
    return redirect(url_for('homepage'))


@app.route('/', methods=['GET', 'POST'])
def check_login():
    """checks login"""
    if request.method == 'POST':
        session.pop('user', None)
    name = request.form['username']
    password = request.form['password']

    if len(name) == 0:
        flash('Username too short, must be 4 characters minimum', "info")
        return redirect(url_for('check_login'))

    h_password = str(get_password_if_registered(name))

    if len(h_password) < 20 or h_password is None:
        flash("Incorrect Username/Password", "info")
        return redirect(url_for('check_login'))

    if sha256_crypt.verify(password, h_password) and h_password is not None:
        session['user'] = request.form['username']
        return redirect(url_for('get_index'))

    flash("Incorrect Username/Password", "info")
    return redirect(url_for('check_login'))


def get_password_if_registered(username_input):
    ''' Check if the given username does not already exist in our password file
    return none of the username does not exist; otherwise return the password for that user
    '''
    try:
        with open(PASSWORD_FILE, "r", encoding="utf-8") as users:
            for record in users:
                if len(record) == 0:
                    print('password file is empty')
                    return None
                username, password = record.split(',')
                password = password.rstrip('\n')
                if username == username_input:
                    return password
    except FileNotFoundError as ex_issue:
        print('File not found: ' + PASSWORD_FILE)
        print(ex_issue.args)
        flash('Database not found...Not available at this time.', "info")
        return redirect(url_for('homepage'))

    except Exception as ex_issue:
        print('No permissions to open this file or data in it not '
              'in correct format: ' + PASSWORD_FILE)
        print(ex_issue.args)
        flash('Not Permissions to open this data with this account.', "info")
        return redirect(url_for('homepage'))

    return None


def check_complexity(password):
    """Checking complexity of the password, checks for length, special
    character, number, uppercase."""
    if len(password) < 12:
        flash('Password too short, must be 12 characters.', "info")
        return False
    if not any(char.isdigit() for char in password):
        flash("Password does not contain a number", "info")
        return False
    has_upper = False
    for temp_character in password:
        if temp_character.isupper():
            has_upper = True
    if not has_upper:
        flash("Password does not contain an Uppercase", "info")
        return False
    special_characters = "!@#$%^&*(()_+|}{][.,></?\""
    if not any(c in special_characters for c in password):
        flash("Password must contain a special character", "info")
        return False
    # Add more complexity for the password check.
    return True


def check_stricter_complex(password):
    """Checks stricter password requirements based on NIST SP 800-63B"""
    try:
        with open(COMMON_PW_FILE, 'r', encoding='utf-8') as common:
            for p_w in common:
                if password == p_w.rstrip('\n'):
                    return False
        return True
    except FileNotFoundError as ex_issue:
        print('File not found: ' + COMMON_PW_FILE)
        print(ex_issue.args)
        flash('Database not found...Not available at this time.', "info")
        return redirect(url_for('profile'))

    except Exception as ex_issue:
        print('No permissions to open this file or data in it not '
              'in correct format: ' + COMMON_PW_FILE)
        print(ex_issue.args)
        flash('Not Permissions to open this data with this account.', "info")
        return redirect(url_for('profile'))


def write_user_to_file(username, password):
    """Write given username and password to the password file"""
    pass_hash = sha256_crypt.hash(password)  # encrypt password before storing to file
    try:  # Add account info to account database
        with open(PASSWORD_FILE, 'a', newline='', encoding="utf-8") as pass_file:
            writer = csv.writer(pass_file)
            writer.writerow([username, pass_hash])
        return
    except FileNotFoundError as ex_issue:
        print("Could not find file called " + PASSWORD_FILE)
        print(ex_issue.args)  # all info about the error printed
        # to the server for support to see/debug
        flash('User Database not available at this time. '
              ' Try again later, or contact support.', "info")
        return
    except Exception as ex_issue:
        print("Could not append to file " + PASSWORD_FILE)
        print(ex_issue.args)  # all info about the error printed
        # to the server for support to see/debug
        flash('User Database not available at this time. '
              ' Try again later or contact support.', "info")
        return


@app.route('/register/', methods=["GET", "POST"])
def register():
    """returns registration template"""
    if request.method == 'GET':
        return render_template("register.html")

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
    if len(username) < 4:
        flash('Username too short, must be 4 characters or more.', "info")
        return redirect(url_for('register'))
    if get_password_if_registered(username) is not None:
        flash(f'Username {username} already exists', "info")
        return render_template('register.html')
    if not check_complexity(request.form['password']):  # Enforce password complexity
        flash('Password must contain the following: 12 characters, 1 upper, 1 lower,'
              ' 1 number, and 1 special character', "info")
        return redirect(url_for('register'))
    write_user_to_file(username, password)
    flash('Registration Successful', "info")
    return redirect(url_for('homepage'))


@app.route('/profile')
def profile():
    """returns the template for profile html page, this page allows
    users to see their account information and change their password"""
    if g.user:
        return render_template('profile.html', user=g.user)
    return redirect(url_for('check_login'))


@app.route('/reset', methods=["GET", "POST"])
def reset():
    """called to check reset password.  first we grab the current password
    and insure the user entered it correctly.  Following Checks: new password
    and old password are not equal.  Then call password complexity"""
    if request.method == 'POST':

        currentpassword = request.form['currentpassword']
        newpassword = request.form['newpassword']

    if not check_stricter_complex(newpassword):  # checks the new password against a common list
        flash(f"{newpassword} is too common. Password must contain the following:"
              f" 12 characters, 1 upper, 1 lower 1 number, and 1 special character", 'info')
        return redirect(url_for('profile'))

    if not check_complexity(newpassword):  # checks the complexity of the password
        flash(f"{newpassword} is not complex enough Password must contain the following:"
              f" 12 characters, 1 upper, 1 lower 1 number, and 1 special character", 'info')
        return redirect(url_for('profile'))

    if current_vs_new_password(currentpassword, newpassword):
        # checks if the new password is same as old
        flash("Password can not be the same as the current password")
        return redirect(url_for('profile'))

    if request.method == 'GET':
        flash('Try again', 'info')
        return redirect(url_for('profile'))

    replace_password(newpassword)
    session.pop('user', None)
    return redirect(url_for('profile'))


def replace_password(password):
    """Replaces the current password with a new one"""
    try:
        with open(PASSWORD_FILE, 'r', encoding='utf-8') as file:
            files_text = file.readlines()

        h_password = sha256_crypt.hash(password) + "\n"
        for i, inbound in enumerate(files_text):
            username = inbound.split(",")
            username = username[0]
            if username == g.user:
                files_text[i] = username + "," + h_password

        with open(PASSWORD_FILE, 'w', encoding='utf-8') as w_file:
            for line in files_text:
                w_file.write(line)

    except FileNotFoundError as ex:
        print(ex.args)
        flash("File Not Found", 'info')
        redirect(url_for('profile'))
    redirect(url_for('profile'))

@app.route('/index')
def get_index():
    """returns the template for the initial home page index"""
    if g.user:
        return render_template("index.html", user=g.user, systems=get_systems_fought(),
                               date_time=dt.datetime.now())
    return redirect(url_for('check_login'))


@app.route('/members')
def get_members():
    """returns the template HTML page for RnK Membership"""
    if g.user:
        return render_template("rnkmembers.html", user=g.user, members=get_member_list(),
                               table_data=get_table_data())
    return redirect(url_for('check_login'))


@app.route('/image')
def get_image():
    """returns the HTML page for the RnK Image"""
    if g.user:
        return render_template("rnkimage.html", user=g.user)
    return redirect(url_for('check_login'))


def current_vs_new_password(current_password, new_password):
    """returns true if the old and new passwords match, and false
    if they do not."""
    if current_password == new_password:
        return True
    return False


def get_member_list():
    """defines the member list that is passed in to the HTML page - rnkmembers.html"""
    members = ["Skrubs", "Lord Maldoror", "Agent Xer0", "Mesh",
               "Elderath", "Trident", "Princess Arcia"]
    members.sort()
    return members


def get_systems_fought():
    """defines the list of regions rooks and kings have conquered in EVE"""
    systems = ["PROVIDENCE", "FOUNTAIN", "GREAT WILDLANDS", "COBALT'S EDGE", "CLOUD RING", "FADE",
               "STAIN", "SCALDING PASS"]
    return systems


def get_table_data():
    """produces data for our members table"""
    table_d = [['Name', 'Position', 'Ship'],
               ['Lord Maldoror', 'CEO', 'Navy Apoc'],
               ['Skrubs', 'Core Member', 'Archon'],
               ['Agent Xer0', 'Core Member', 'Archon'],
               ['Mesh', 'Director', 'Navy Apoc'],
               ['Elderath', 'Core Member', 'Navy Apoc'],
               ['Trident', 'Core Member', 'Navy Apoc'],
               ['Princess Arcia', 'Core Member', 'Navy Apoc']]
    return table_d


if __name__ == '__main__':
    app.secret_key = os.urandom(24)
    app.run(debug=True)
