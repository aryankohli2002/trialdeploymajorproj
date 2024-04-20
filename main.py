from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_wtf.csrf import CSRFProtect
from database import delete_app_password, add_password_for_apps, load_app_passwords_from_db, \
get_user_phoneno, user_login, register_new_user, update_app_username, update_app_password, \
check_if_user_exists, check_user_reset_details, fetch_username_for_password_reset, reset_password
from otp import *
from aess import generate_key


app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = generate_key()
app.config['PERMANENT_SESSION_LIFETIME'] = 600 #in seconds
csrf = CSRFProtect(app)


@app.route('/')
def show_login():
  return render_template('login.html', error=None)


@app.route('/register')
def register():
   return render_template('register.html')
           

@app.route('/register', methods=['POST'])
def register_user():
  if request.method == 'POST':
    username = request.form.get('username')
    if check_if_user_exists(username):
        error = 'Username already exists. Please choose a unique username'
        return render_template('register.html', error=error)
    else:
        session['username'] = username
        session['password'] = request.form.get('password')
        session['email'] = request.form.get('email')
        session['phoneno'] = request.form.get('phonenumber')
        register_new_user()
        return redirect(url_for('show_login'))


@app.route('/login', methods=['POST' , 'GET'])
def login():
  if request.method == 'POST':
    username = request.form['login_username']
    if check_if_user_exists(username):
        password = request.form['login_password']
        # If user exists, check login credentials
        if user_login(username, password):
            session['phoneno'] = get_user_phoneno(username, password)
            session['username'] = username
            session['password'] = password
            #return redirect(url_for('otp_verification'))
            return redirect(url_for('passwordstorage'))
        else:
            error = "Invalid password! Try again."
            return render_template('login.html', error=error)
    else:
        error = "User does not exist. Please register first."
        return render_template('login.html', error=error)
  else:
    return render_template('login.html', error=None)


@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    error = None
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if username is not set
      
    if request.method != 'POST':
      send_otp() 
    elif request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:  # Check if OTP is empty
            error = 'Please enter OTP.'
        else:
            session['otp'] = otp
            if verify_otp():
                return redirect(url_for('passwordstorage'))
            else:
                error = 'Invalid OTP. Please try again.'
    
    return render_template('otp.html', error=error)

    
@app.route('/passwordstorage')
def passwordstorage():
  if 'username' not in session:
    return redirect(url_for('login'))  # Redirect to login if username is not set
  
  username = session['username']
  return render_template('passwordstorage.html', userPassword=load_app_passwords_from_db(), mainusr=username)


@app.route('/edit/<passwordid>', methods=['GET','POST'])
def editbutton(passwordid):
   session['passwordid'] = passwordid
   return render_template('editbutton.html', p=passwordid)

   
@app.route('/submit', methods=['GET','POST'])
def submit():
    text_info = request.form['text_info']
    update_option = request.form['update_option']
    passwordid = session['passwordid']

    if update_option == 'Username':
      if update_app_username(text_info, passwordid):
        return redirect(url_for('passwordstorage'))
    elif update_option == 'Password':
       update_app_password(text_info, passwordid)
       return redirect(url_for('passwordstorage'))
    else:
       return 'error'


@app.route('/delete/<passwordid>', methods=['GET', 'POST'])
def delete(passwordid):
  delete_app_password(int(passwordid))
  return redirect(url_for('passwordstorage'))


@app.route('/add_new_record', methods=['POST'])
def add_new_record():
    website = request.form['website']
    username_on_website = request.form['username']
    password = request.form['password']
    add_password_for_apps(website, username_on_website, password)
    return redirect(url_for('passwordstorage'))

@app.route('/resetLogin', methods=['POST', 'GET'])
def resetLogin():

  if request.method == 'POST':
    phoneno = request.form['phoneNumber']
    email = request.form['emailAddress']
    session['email'] = email
    session['phoneno'] = "+91"+phoneno

    if request.form['submitbtn'] == 'sendOTP':
      if check_user_reset_details():
        send_otp()
        return render_template('resetLogin.html', phoneno = phoneno, email = email)
      else:
        error = "Invalid phoneno or email! Try again"
        return render_template('resetLogin.html', error=error, phoneno = phoneno, email = email)
      
    elif request.form['submitbtn'] == 'verifyOTP':
       session['otp'] = request.form['otp']
       if verify_otp():
          
          return redirect(url_for('newLoginDetails'))
       else:
          error = "Invalid OTP. Please try again"
          return render_template('resetLogin.html', error=error)
       
  elif request.method =='GET':
    return render_template('resetLogin.html', error=None)
  
  else:
    error = "Invalid request"
    return render_template('resetLogin.html', error=error)


@app.route('/newLoginDetails', methods=['POST', 'GET'])
def newLoginDetails():
  username = fetch_username_for_password_reset()
  session['username'] = username

  if request.method == 'POST':
    password = request.form.get('new_password')
    session['password'] = password
    reset_password()
    return redirect(url_for('login'))
  
  else:
      return render_template('newLoginDetails.html', username=username)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# @app.errorhandler(404)
# def page_not_found(error):
#     return render_template('404.html'), 404  # Return a custom 404 error page

# @app.errorhandler(405)
# def method_not_allowed(error):
#     return render_template('405.html'), 405  # Return a custom 405 error page


if __name__ == "__main__":
  app.run(port=8080, debug=True)
