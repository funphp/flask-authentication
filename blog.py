from flask import Flask, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from wtforms.widgets import TextArea
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '\x10\x0eB\x9c$\xaa\xe3\xcd$y\xa1\xa9\x8f\x93\xf7VQ\xa1\xfb\rN,\x9b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:123456@192.168.33.22/flask_blog'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
Bootstrap(app)
login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
""" Post form"""
class PostForm(FlaskForm):
    title = StringField('title', validators =[InputRequired(), Length(min=3)])
    content = StringField('content', widget=TextArea(), validators =[InputRequired(), Length(min=3)])


"""Login form"""
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=10)])
    password = StringField('password', validators=[InputRequired(), Length(min=4)])
    remember = BooleanField('remember_me')

"""Registraiton form"""
class RegistrationForm(FlaskForm):
    username = StringField('username', validators =[InputRequired(), Length(min=4, max=10)])
    password = StringField('password', validators = [InputRequired(), Length(min=4)])
    email = StringField('email', validators = [InputRequired(), Email(message='Invalid Email'), Length(min=8, max=80)])
"""Post model"""
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.String(500))
    user_id = db.Column(db.Integer)

"""User Model"""
class User(UserMixin, db.Model):
    id =db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique = True)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(250))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    post = db.session.query(Post.id, Post.title,Post.content, User.username).filter(Post.user_id == User.id)

    return render_template('index.html', postlist=post)

@app.route('/login', methods= ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/register',methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hash_password = generate_password_hash(form.password.data)
        user = User(
            username = form.username.data,
            email = form.email.data,
            password = hash_password
        );
        db.session.add(user)
        db.session.commit()
        flash('New user created')
        return redirect(url_for('index'))

    return render_template('register.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


"""blog post route"""
@app.route('/post',methods=['GET', 'POST'])
@login_required
def post():
    postForm = PostForm()
    if postForm.validate_on_submit():
        post = Post(
            title = postForm.title.data,
            content = postForm.content.data,
            user_id = current_user.id
        )
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully')
        return redirect(url_for('post'))
    return render_template('post.html', form=postForm)

if __name__ =='__main__':
    app.run()