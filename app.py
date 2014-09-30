# -*- coding: cp1251 -*-

from gevent import monkey
monkey.patch_all()

import time
from threading import Thread
from flask import Flask, render_template, session, request,redirect,url_for, flash
from flask.ext.socketio import SocketIO, emit, join_room, leave_room

from flask.ext.bootstrap import Bootstrap
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import Required, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask.ext.mail import Mail, Message

from threading import Thread
import os


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.debug = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') 
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') 

app.config['FLASK_MAIL_SUBJECT_PREFIX'] = '[FlaskChat.pythonanywhere.com]'
app.config['FLASK_MAIL_SENDER'] = 'FlaskChat Admin ' + str(os.environ.get('MAIL_USERNAME'))
app.config['FLASK_ADMIN'] = os.environ.get('MAIL_USERNAME') 



socketio = SocketIO(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.session_protection= "strong"
login_manager.login_view = "login"
login_manager.init_app(app)
mail = Mail(app)
db = SQLAlchemy(app)

thread = None



class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(512))


    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)



class Channels(db.Model):
    __tablename__= "channels"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    description = db.Column(db.String(128), unique=False, index=True)


class Posts(db.Model):
    __tablename__= "posts"
    id = db.Column(db.Integer, primary_key=True)
    channel = db.Column(db.String(64), unique=False, index=True)
    post = db.Column(db.String(256), unique=False, index=True)
    
#########################################################################################################

class LoginForm(Form):
    email = StringField("Email:", validators=[Required(), Length(1,64), Email()])
    password = PasswordField("Password:", validators=[Required()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")

#########################################################################################################

class RegistrationForm(Form):
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

#########################################################################################################
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASK_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['FLASK_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr= Thread(target = send_async_email, args=[app, msg])
    thr.start()
    return thr

#########################################################################################################

@app.errorhandler(403)
def forbidden(a):
    return render_template("err/403.html"), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template("err/404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("err/500.html"), 500


#########################################################################################################


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route("/register", methods = ['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        user = User(email=form.email.data, \
        username=form.username.data, \
        password=form.password.data)

        db.session.add(user)

        send_email(form.email.data, "Welcome to FlaskChat!", "mail/welcome_user" , \
                   email=form.email.data, password = form.password.data)
        send_email(app.config["FLASK_ADMIN"], "New User Registered", "mail/new_user", username=form.username.data)

        flash('You can now login')
        session["alert_type"] = 1 #Successfull registration
        return redirect(url_for("login"))
    return render_template("auth/register.html", form=form)




@app.route("/login", methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            session["alert_type"] = 1
            flash("Welcome, " + user.username + " !")
            session["alert_type"] = 1 #Successfull login
            return redirect(url_for("chat", channel = "Common")) #render_template("auth/chat.html", channel = 'common')
            #return redirect(url_for("chat"))
        else:
            flash("Invalid username or password.")
            session["alert_type"] = 0 #Fault during login (wrong login or password)
    return render_template("auth/login.html", form=form, alert_type = session["alert_type"])



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    session["alert_type"] = None #Unauthorized access to the personal chat page
    return redirect(url_for("login"))


@app.route('/')
def index():
    if "alert_type" not in session:
        session["alert_type"] = None

    if current_user.is_authenticated():
        return redirect(url_for("chat", channel = "Common"))
    else:
        return redirect(url_for("register"))












@app.route('/chat/<channel>', methods = ['GET', 'POST'])
@login_required
def chat(channel):
    findHistoryRes = Posts.query.filter_by(post= "")
    #Получить "пустой результат" на случай если пост-вызов по созданию канала а не по поиску
    findChannelsRes=Channels.query.filter_by(name= "")
    #Если форма вызвана по Посту (только при создании нового канала, при поиске каналов и поиске в истории)
    if len(request.form) > 0:
        
        #Если вызов по поиску то получить переданный запрос
        if "search_name" in request.form:
            findChannelName = request.form["search_name"]
            #Если строка запроса поиска канала не пустая
            if len(findChannelName) > 0:
                findChannelsRes = db.session.query(Channels).filter(Channels.name.like('%' + findChannelName + '%'))
                
        if "search_history" in request.form:
            findHistory = request.form["search_history"]
            if len(findHistory) > 0:
                findHistoryRes = db.session.query(Posts).filter(Posts.post.like('%' + findHistory + '%'))
            
        #Если пост-запрос связан с созданием канала
        if "channel_name" in request.form and "channel_desc" in request.form:
            #то взять переданные данные по новому чат-каналу (имя и описание)
            newChannelName = request.form["channel_name"]
            newChannelDesc = request.form["channel_desc"]
            #Если есть все данные и допустимой для БД длинны то
            if (len(newChannelName) > 0 and len(newChannelName) <=64 \
                and len(newChannelDesc) > 0 and len(newChannelDesc) <=128):
                #проверить существует ли такой канал уже в базе
                newChannel = Channels.query.filter_by(name = newChannelName).first()
                #Если такой канал еще не существует то
                if newChannel is None:
                    #создать его
                    newChannel = Channels(name = newChannelName, description = newChannelDesc)
                    #внести в базу данных существующих каналов
                    db.session.add(newChannel)
                    #Изменить имя текущего канала
                    channel = newChannelName
                    #Установить флаг успеха операции
                    session["alert_type"]= 1
                    #сформировать сообщение об успехе создания нового канала
                    flash("New channel " + channel + " created.")
                    #Перейти на новосозданный канал по Гету
                    return redirect(url_for("chat", channel = channel))
                #Если такой канал уже существует в БД каналов
                else:
                    #Установить флаг неудачи операции
                    session["alert_type"]= 2
                    #Сформировать сообщение о типе неудачи при создания нового канала 
                    flash("Channel " + newChannelName + " already exists.")
            #Если указаны не все данные или данные недопустимой длинны
            else:
                #Установить флаг неудачи последней операции 
                session["alert_type"]= 2
                #Сформитровать сообщение о типе неудачи
                flash("Some fields empty or too long. Channel was not created.")

 
    #Орисовать страницу с переданными значениями     
    return render_template('auth/chat.html',
                           #Передать текущий канал
                           channel = channel,
                           #Получить список всех текущих кналов
                           allChannels = db.session.query(Channels).all(),
                           #Передать результат поиска канала по имени
                           findChannelsRes = findChannelsRes,
                           #Передать последние 20 постов для данного канала
                           lastPosts = db.session.query(Posts).order_by(desc(Posts.id)).filter_by(channel=channel).limit(20)[::-1],
                           findHistoryRes = findHistoryRes,
                           #Передать код сообщения
                           alert_type = session["alert_type"])


@socketio.on('my event', namespace='/test')
def test_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': message['data'], 'count': session['receive_count']})


@socketio.on('my broadcast event', namespace='/test')
def test_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': message['data'], 'count': session['receive_count']},
         broadcast=True)


@socketio.on('join', namespace='/test')
def join(message):
    join_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    


@socketio.on('leave', namespace='/test')
def leave(message):
    leave_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    

@socketio.on('my room event', namespace='/test')
def send_room_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
            
    emit('my response',
         {'data': message['data'], 'count': session['receive_count']},
         room=message['room'])
    #Сохранить пост в БД
    db.session.add(Posts(channel=message['room'], post=message['data']))

    

@socketio.on('connect', namespace='/test')
def test_connect():
    emit('my response', {'data': 'Connected', 'count': 0})


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    socketio.run(app, port=80)
