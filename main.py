from flask import Flask, render_template, redirect, url_for, request, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField, DateField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_required, LoginManager, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.fields.html5 import DateField




app = Flask(__name__)
app.config['SECRET_KEY'] = "SECRET_KEY"
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    all_todos = relationship("Todo", back_populates="author")


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="all_todos")


    title = db.Column(db.String(100), nullable=False)
    complete = db.Column(db.Boolean)


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("REGISTER")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("LOG IN")


class DoForm(FlaskForm):
    title = StringField("Write your task", validators=[DataRequired()])
    date = DateField('Pick a date',)

    submit = SubmitField("Add")


db.create_all()




@app.route('/', methods=['GET', 'POST'])
def home():
    form = DoForm()
    if current_user.is_authenticated:
        todo_list = Todo.query.filter_by(author_id=current_user.id)
    else:
        todo_list = None
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to add a to-do item.")
            return redirect(url_for('home'))
        date = form.date.data.strftime('%Y-%m-%d')
        title = form.title.data
        new_todo = Todo(title=title,author=current_user,complete=False,date=date)
        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('index.html', form=form, todo_list=todo_list, current_user=current_user)



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already registered.")
            return redirect((url_for('login')))
        new_user = User()
        new_user.author = current_user
        new_user.email = form.email.data
        new_user.name = form.name.data
        hashed_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user.password = hashed_password
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html', form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email is not exist.")
        elif not check_password_hash(user.password, password):
            flash("Password is wrong.")
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html', form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/update/<int:todo_id>', methods=['GET', 'POST'])
def update(todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    todo.complete = not todo.complete
    db.session.commit()
    return redirect(url_for('home'))



@app.route('/delete/<int:todo_id>', methods=['GET', 'POST'])
def delete(todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
