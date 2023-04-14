from flask import Flask, render_template, request, flash, redirect, url_for, session,current_app
import sqlite3
from flask_mail import Mail, Message
import random
from random import randint
from os.path import exists
import os
import string
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer
import cloudinary
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url







ALLOWED_EXTENSIONS = set(['png','jpg','jpeg','gif','svg','webp','apng','avif'])




app = Flask(__name__)
cloudinary.config(
  cloud_name = "dmpfik5wz",
  api_key = "987867663248676",
  api_secret = "ZiKxpwDHnmTQrrxYiI9DHTwXbnU",
  secure = True,
  use_filename = False,
  unique_filename = False
)
app.config['SECRET_KEY'] = '123'
app.config['SECURITY_PASSWORD_SALT'] = 'MY_SALT'
app.config['UPLOAD_FOLDER']='static/usersprofile'

mail = Mail()

app.config.update(MAIL_SERVER='smtp.gmail.com', MAIL_PORT='465',
                  MAIL_USE_SSL=True,
                  MAIL_USERNAME='agyawali78@gmail.com',
                  MAIL_PASSWORD='oiqzxkszuqsqespy')
mail.init_app(app)

con = sqlite3.connect('database.db')
con.execute('create table if not exists customer(sno integer primary key,firstname text,lastname text,email text unique,phone integer,password text,bio text,twitter text,facebook text,instagram text,github text,whatsapp text,image text)'
            )
con.close()


def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1) [1].lower() in ALLOWED_EXTENSIONS






def get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])




def generate_token(email):
    serializer = get_serializer()
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

cloudupload="https://res.cloudinary.com/dmpfik5wz/image/upload/v1679660252/"



def verify_token(token, expiration=3600):
    serializer = get_serializer()
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return None
    return email








@app.route('/')
def index():
    try:
        session['email']
    except KeyError:
        session['email'] = 'test'
    try:
	    session['imageurl']
    except KeyError:
	    session['imageurl']=cloudupload +'/user.png.jpg'
    try:
	    session['profile']
    except KeyError:
	    session['profile']='user.png'
    
    finally:
	    subject=["English","Nepali","Maths","Computer","Social","Accountancy","Economics","Optional-Maths","Agriculture"]
	    grade=["Grade-8" , "Grade-10" , "Grade-12"]
	    session['sulist']= [random.choice(subject) for x in range(16)]
	    session['gradelist']= [random.choice(grade) for x in range(16)]
	    session['brand']="NEG.EDU.NP"
	    session['suscrolllist']= [random.choice(subject) for x in range(16)]
	    session['gradescrolllist']= [random.choice(grade) for x in range(16)]
	    
    return render_template('index.html')


@app.route('/questions/BLE-Model-Questions')
def BLE():
    return render_template('BLE.html')


@app.route('/questions/SEE-Model-Questions')
def SEE():
    return render_template('SEE.html')


@app.route('/questions/12th-Boards-Model-Questions')
def XII():
    return render_template('XII.html')


@app.route('/privacy-policy')
def pp():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'

    return render_template('pp.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'
    if session['email'] == 'test':
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            con = sqlite3.connect('database.db')
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('select * from customer where email=? and password=?', (email, password))
            tur = con.cursor()
            tur.execute('select * from customer where phone=? and password=?', (email, password))
            data = cur.fetchone()
            datap = tur.fetchone()
            
            if data:
                session['sno'] = data['sno']
                session['bio'] = data['bio']
                session['twitter'] = data['twitter']
                session['instagram'] = data['instagram']
                session['facebook'] = data['facebook']
                session['github'] = data['github']
                session['whatsapp'] = data['whatsapp']
                session['firstname'] = data['firstname']
                session['lastname'] = data['lastname']
                session['email'] = data['email']
                session['password'] = data['password']
                session['phone'] = data['phone']
                session['profile'] = data['image']
                session['imageurl'] = cloudupload+session['profile']+".jpg"
                
                return redirect('dashboard')
            elif datap:
	            session['sno'] = datap['sno']
	            session['bio'] = datap['bio']
	            session['twitter'] = datap['twitter']
	            session['instagram'] = datap['instagram']
	            session['facebook'] = datap['facebook']
	            session['github'] = datap['github']
	            session['whatsapp'] = datap['whatsapp']
	            session['firstname'] = datap['firstname']
	            session['lastname'] = datap['lastname']
	            session['email'] = datap['email']
	            session['password'] = datap['password']
	            session['phone'] = datap['phone']
	            session['profile'] = data['image']
	            session['imageurl'] = cloudupload+session['profile']+".jpg"
	            
	            return redirect('dashboard')
            else:

                       # return (session['firstname'])

                flash('Invalid Credentials', 'danger')
    else:
        flash('You are already logged in', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('login.html')




@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'

    if session['email'] == 'test':
        flash("You're not logged in", 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/signup', methods=['POST', 'GET'])
def signup():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'

    if session['email'] != 'test':
        flash('Your are already logged in', 'danger')
        return redirect(url_for('dashboard'))
    else:

        if request.method == 'POST':
            try:
                firstname = request.form['firstname']
                lastname = request.form['lastname']
                email = request.form['email']
                phone = request.form['phnnbr']
                password = request.form['password1']
                cpass = request.form['password2']
                con = sqlite3.connect('database.db')
                cur = con.cursor()
                if password == cpass:
                    cur.execute('insert into customer(firstname,lastname,email,phone,password)values(?,?,?,?,?)'
                                , (firstname, lastname, email, phone,
                                password))
                    con.commit()
                    con.close()

                    con = sqlite3.connect('database.db')
                    con.row_factory = sqlite3.Row
                    cur = con.cursor()
                    cur.execute('select * from customer where email=? and password=?'
                                , (email, password))
                    data = cur.fetchone()
                    if data:
                        session['sno'] = data['sno']
                        session['bio'] = data['bio']
                        session['twitter'] = data['twitter']
                        session['instagram'] = data['instagram']
                        session['facebook'] = data['facebook']
                        session['github'] = data['github']
                        session['whatsapp'] = data['whatsapp']
                        session['firstname'] = data['firstname']
                        session['lastname'] = data['lastname']
                        session['email'] = data['email']
                        session['password'] = data['password']
                        session['phone'] = data['phone']
                        session['profile'] = data['image']
                        session['imageurl'] = cloudupload+session['profile']+".jpg"
                        
                        flash('Successfully Registered', 'success')
                        return redirect('dashboard')
                else:
                    flash('Password amd Confirm Password do not match',
                          'danger')
            except:
                flash('SignUp Failed', 'danger')

    return render_template('signup.html')

"""
@app.route('/dashboard/edit-profile', methods=['GET', 'POST'])
def edit():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'
    if request.method=='POST':
	    try:
	    
		    if 'image' not in request.files:
			    flash('Error! Image could not be uploaded','danger')
		    
		    file = request.files['image']
		    if allowed_file(file.filename) or file.filename=='':
			    image = secure_filename(file.filename)
			    file_exists = exists('static/usersprofile/'+image)
		    
		    if image!='':
			    file.save(os.path.join(app.config['UPLOAD_FOLDER'],image))
		    sno = session['sno']
		    if image!='' and session['profile']!='user.png' and image!=session['profile']:
			    os.remove(session['imageurl'])
		    if image=='' and session['profile']=='':
			    image='user.png'
		    if session['profile']!='' and image=='':
			    image=session['profile']
		    
		    session['profile']='user.png'
		    bio = request.form['bio']
		    facebook = request.form['facebook']
		    instagram = request.form['instagram']
		    twitter = request.form['twitter']
		    github = request.form['github']
		    whatsapp = request.form['whatsapp']
		    con = sqlite3.connect('database.db')
		    cur = con.cursor()
		    cur.execute('UPDATE customer SET  bio=?,facebook=?,instagram=?,twitter=?,github=?,whatsapp=?,image=? WHERE sno = ?;', (bio,facebook,instagram,twitter,github,whatsapp,image,sno))
		    con.commit()
		    session['bio'] = bio
		    session['facebook'] = facebook
		    session['instagram'] = instagram
		    session['twitter'] = twitter
		    session['github'] = github
		    session['whatsapp'] = whatsapp
		    session['imageurl'] = 'static/usersprofile/'+image
		    session['profile'] = image
		    flash('Successfully Updated', 'success')
		    return redirect(url_for('dashboard'))
		    
	    except:
		    flash('Update failed', 'danger')
	    

    
    return render_template('editprofile.html')

"""






@app.route('/dashboard/edit-profile', methods=['GET', 'POST'])
def edit():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'
    if request.method=="POST":
	    try:
	    
		    if 'image' not in request.files:
			    flash('Error! Image could not be uploaded','danger')
		    
		    file = request.files['image']
		    if allowed_file(file.filename) or file.filename=='':
			    image = secure_filename(file.filename)
			    #file_exists = exists('static/usersprofile/'+image)
		    for r in ((".jpg", ""), (".png", ""),(".svg", ""), (".jpeg", ""),(".gif", ""), (".webp", ""),(".apng", ""), (".avif", "")):
			    imagei = image.replace(*r)
		    if image!='' and image!=session['profile']:
			    #file.save(os.path.join(app.config['UPLOAD_FOLDER'],image))
			    cloudinary.uploader.upload(file, public_id=image)
		    sno = session['sno']
		    if image!='' and session['profile']!='user.png' and image!=session['profile']:
			    #os.remove(session['imageurl'])
			    cloudinary.uploader.destroy(session['profile'])
		    if image=='' and session['profile']=='':
			    image='user.png'
		    if session['profile']!='' and image=='':
			    image=session['profile']
		    
		    session['profile']='user.png'
		    bio = request.form['bio']
		    facebook = request.form['facebook']
		    instagram = request.form['instagram']
		    twitter = request.form['twitter']
		    github = request.form['github']
		    whatsapp = request.form['whatsapp']
		    con = sqlite3.connect('database.db')
		    cur = con.cursor()
		    cur.execute('UPDATE customer SET  bio=?,facebook=?,instagram=?,twitter=?,github=?,whatsapp=?,image=? WHERE sno = ?;', (bio,facebook,instagram,twitter,github,whatsapp,image,sno))
		    con.commit()
		    session['bio'] = bio
		    session['facebook'] = facebook
		    session['instagram'] = instagram
		    session['twitter'] = twitter
		    session['github'] = github
		    session['whatsapp'] = whatsapp
		    session['imageurl'] = cloudupload+image+".jpg"
		    session['profile'] = image
		    flash('Successfully Updated', 'success')
		    return redirect(url_for('dashboard'))
		    
	    except:
		    flash("Update Failed","danger")
		 
	    

    
    return render_template('editprofile.html')

























@app.route('/logout')
def logout():
    session.clear()
    session['email'] = 'test'
    return redirect(url_for('login'))

otp = randint(000000, 999999)


@app.route('/dashboard/edit-account', methods=['GET', 'POST'])
def editaccount():

    try:
        session['email']
    except KeyError:
        session['email'] = 'test'

    if request.method == 'POST':
        editemail = request.form['email']
        editphone = request.form['phone']
        editpassword = request.form['password']
        ma = 'Dear ' + session['firstname'] \
            + ' ! Your OTP from  NEG.EDU.NP'
        msg = Message("OTP | NEG.EDU.NP",sender='publicgyawali@gmail.com',recipients=[session['email']])
        msg.body = ma + "             														" + str(otp)
        mail.send(msg)
        session['editemail'] = editemail
        session['editphone'] = editphone
        session['editpassword'] = editpassword
        return redirect(url_for('validate'))

    return render_template('editaccount.html')


@app.route('/dashboard/validate', methods=['GET', 'POST'])
def validate():
    if request.method == 'POST':
        otp1 = request.form['otp1']
        otp2 = request.form['otp2']
        otp3 = request.form['otp3']
        otp4 = request.form['otp4']
        otp5 = request.form['otp5']
        otp6 = request.form['otp6']
        user_otp = otp1 + otp2 + otp3 + otp4 + otp5 + otp6
        if otp == int(user_otp):
            try:
                sno = session['sno']
                editemail = session['editemail']
                editphone = session['editphone']
                editpassword = session['editpassword']
                con = sqlite3.connect('database.db')
                cur = con.cursor()
                cur.execute('UPDATE customer SET  email=?,phone=?,password=? WHERE sno = ?;'
                            , (editemail, editphone, editpassword, sno))
                con.commit()
                session['email'] = editemail
                session['phone'] = editphone
                session['password'] = editpassword
                flash('Account Updated', 'success')
                flash('Session expired! please re-login', 'danger')
                session.clear()
                session['email'] = 'test'
                return redirect(url_for('login'))
            except:
                flash('Update failed', 'danger')
        else:

            # return redirect(url_for("dashboard"))

            return "<h3><a href='/dashboard/edit-account'>Wrong Verification Code Please try again!</a></h3>"

    return render_template('verify.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        session['forgotemail']=email
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        cur.execute('Select * from customer where email =?',(email,))
        data = cur.fetchone()
        if data:
             # You can send an email to the user with the reset password link including the reset token
            
            token = generate_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            message = Message(
            'Password Reset Request',
            sender='noreply@domain.com',
            recipients=[email]
            )
            message.body = f'The provided code will expire in an hour.To reset your password, visit the following link: {reset_url}'
            mail.send(message)
            flash('Please check your email for instructions to reset your password', 'info')
            
            return redirect(url_for('login'))
        else:
            flash('Email is not associated with any account', 'error')
    return render_template('forgot_password.html')



@app.route('/Grade-8/<subject>')
def subject8(subject):
	return render_template('g8sub.html',subject=subject)
	
	
	
@app.route('/Grade-10/<subject>')
def subject10(subject):
	return render_template('g10sub.html',subject=subject)
	



@app.route('/Grade-12/<subject>')
def subject12(subject):
	return render_template('g12sub.html',subject=subject)







@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if email:
	    if request.method == 'POST':
		    password = request.form['password']
		    confirm_password = request.form['cpassword']
		    if password != confirm_password:
			    flash('Passwords do not match.', 'danger')
		    else:
			    con = sqlite3.connect('database.db')
			    forgotemail=session['forgotemail']
			    cur = con.cursor()
			    cur.execute('UPDATE customer SET password=? WHERE email = ?;'
			    , (password, forgotemail))
			    con.commit()
			    con.close()
			    session.clear()
			    session['email'] = 'test'
			    flash('Your password has been reset.', 'success')
			    return redirect(url_for('login'))
			    
			    
			    
    else:
	    flash('Invalid or expired token.', 'danger')
	    return redirect(url_for('forgot_password'))
			    
			    
			    
    return render_template('reset_password.html')


@app.route('/about-us')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contact-us' , methods=['GET','POST'])
def contactus():
	if request.method=="POST":
		name = request.form['nae']
		email = request.form['email']
		subject = request.form['subject']
		reciever='contact@abhinavgyawali.ml'
		ma = 'Mail From contact form ' + 'by :- ' + name + ' email :- ' + email
		msg = Message("Mail From | NEG.EDU.NP " + name,sender=email,recipients=[reciever])
		msg.body = ma +" Subject :- " + subject
		mail.send(msg)
	return render_template('contactus.html')



@app.route('/ads.txt')
def ads():
    return render_template('ads.txt')












@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404
    
    
    
    
    

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500












if __name__ == '__main__':
    app.run(port=os.getenv('PORT', default=5000))