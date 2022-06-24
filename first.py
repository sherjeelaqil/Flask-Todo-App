from email.policy import default
from gettext import NullTranslations
from operator import and_
from telnetlib import LOGOUT
from tkinter import NONE
from xmlrpc.client import boolean
import bcrypt
import flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, all_, desc, null
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
    user_accessed,
)
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask import *
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config["SECRET_KEY"] = "THISISAKEY"
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:1234@localhost/personal"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    sno = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    def get_id(self):
        return self.sno

class Todo(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.Integer, default=null, nullable=False)

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title}"



class Controller(ModelView):
    def is_accessible(self):
        if current_user.is_admin==True:
            return current_user.is_authenticated
        else:
            return abort(404)
        # return current_user.is_authenticated
    def not_auth(self):
        return 'not autherized'
    
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if current_user.is_admin==True:
            return current_user.is_authenticated

admin = Admin(app, name='Admin', index_view=MyAdminIndexView(),url="/admin")
admin.add_view(Controller(User,db.session))
admin.add_view(Controller(Todo,db.session))

class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"},
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        if existing_user_name:
            raise ValidationError(
                "Username already exists. Please choose a different one."
            )


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"},
    )
    submit = SubmitField("Login")


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("todo"))
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("todo"))
    
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                if current_user.is_admin:
                    return redirect(url_for("todo"))#admin.index
                return redirect(url_for("todo"))
            else:
                error = "Invalid password. Please Enter correct password"
        else:
            error = "Username is not registered"

    return render_template("login.html", form=form, error=error)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # print(form.password.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    if current_user.is_authenticated:
        return redirect(url_for("todo"))

    return render_template("register.html", form=form)

@app.route("/add_user", methods=["GET", "POST"])
@login_required
def add_user():
    form = RegisterForm()

    if request.method == "POST":
        # print(form.password.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        new_user = User(username=form.username.data, password=hashed_password, is_admin = bool(int(request.form["admin"])))
        db.session.add(new_user)
        db.session.commit()
        flash("User Added Successfully")
        return redirect("/manage_users")


    return render_template("add_user.html", form=form, user=User)

@app.route("/todo", methods=["GET", "POST"])
@login_required
def todo():
    alltodo=null
    if request.method == "POST":
        todo = Todo(title=request.form["title"], desc=request.form["desc"], user = current_user.sno)
        db.session.add(todo)
        db.session.commit()
    # if current_user.is_admin:
    #     # alltodo =Todo.query.join(User,Todo,Todo.user==User.sno).all()
    #     alltodo =db.session.query(User.username,Todo.sno,Todo.title,Todo.desc,Todo.date_created).join(Todo,and_(Todo.user==User.sno)).all()
    #     # query(User,Todo).filter(User.sno == Todo.user).all()
    #     # alltodo = Todo.query.all()
    # else:
    alltodo = Todo.query.filter(Todo.user==current_user.sno).all()
    session['my_var']=request.base_url
    return render_template("index.html", alltodo=alltodo, current_user=current_user, User=User)

@app.route("/manage_todos", methods=["GET", "POST"])
@login_required
def manage_todos():
    alltodo=null
    if request.method == "POST":
        todo = Todo(title=request.form["title"], desc=request.form["desc"], user = current_user.sno)
        db.session.add(todo)
        db.session.commit()
    if current_user.is_admin:
        # alltodo =Todo.query.join(User,Todo,Todo.user==User.sno).all()
        alltodo =db.session.query(User.username,Todo.sno,Todo.title,Todo.desc,Todo.date_created).join(Todo,and_(Todo.user==User.sno)).all()
        # query(User,Todo).filter(User.sno == Todo.user).all()
        # alltodo = Todo.query.all()
    else:
        alltodo = Todo.query.filter(Todo.user==current_user.sno).all()
    
    session['my_var']=request.base_url

    return render_template("manage_todos.html", alltodo=alltodo, current_user=current_user, User=User)


@app.route("/manage_users", methods=["GET", "POST"])
@login_required
def manage_users():
    allusers = User.query.filter().all()
    session['my_var']=request.base_url
    return render_template("manage_users.html", User=allusers)




@app.route("/show")
def show():
    alltodo = Todo.query.all()
    return "<p>This is products page</p>"


@app.route("/update/<int:sno>", methods=["GET", "POST"])
@login_required
def update(sno):

    link=session['my_var'].rpartition('/')
    link_route=link[len(link)-1]
    if request.method == "POST":
        title = request.form["title"]
        desc = request.form["desc"]
        todo = Todo.query.filter_by(sno=sno).first()
        todo.title = title
        todo.desc = desc
        db.session.add(todo)
        db.session.commit()
        return redirect("/"+link_route)
    todo = Todo.query.filter_by(sno=sno).first()
    return render_template("update.html", todo=todo)

@app.route("/update_user/<int:sno>", methods=["GET", "POST"])
@login_required
def update_user(sno):
    link=session['my_var'].rpartition('/')
    link_route=link[len(link)-1]
    if request.method == "POST":
        username = request.form["name"]
        is_admin = request.form["admin"]
        user = User.query.filter_by(sno=sno).first()
        user.username = username
        user.is_admin = bool(int(is_admin))
        db.session.add(user)
        db.session.commit()
        flash("User Updated Succesfully")
        return redirect("/"+link_route)
    user = User.query.filter_by(sno=sno).first()
    # print(user.is_admin)
    return render_template("update_user.html", user=user)


@app.route("/change_password/<int:sno>", methods=["GET", "POST"])
@login_required
def change_password(sno):
    error = None
    link=session['my_var'].rpartition('/')
    link_route=link[len(link)-1]
    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        user = User.query.filter_by(sno=sno).first()
        # hashed_pass=bcrypt.generate_password_hash(old_password).decode("utf-8")
        # print(new_password,'************************',link_route,user.password)
        # print('--------------------------')
        if bcrypt.check_password_hash(user.password,old_password):
            password=bcrypt.generate_password_hash(new_password).decode("utf-8")
            user.password = password
            db.session.add(user)
            db.session.commit()
            # print(new_password,'***--------*********', password,'+++++++++++++++++++++++',link_route)
            flash("Password Changed Succesfully")
            return redirect("/"+link_route)
        else:
            error = "Invalid password. Please Enter correct password"
    user = User.query.filter_by(sno=sno).first()
    return render_template("change_password.html", user=user, error=error)




@app.route("/delete/<int:sno>")
@login_required
def delete(sno):
    link=session['my_var'].rpartition('/')
    link_route=link[len(link)-1]
    todo = Todo.query.filter_by(sno=sno).first()
    db.session.delete(todo)
    db.session.commit()
    flash("Todo Deleted Successfully")
    return redirect("/"+link_route)


@app.route("/delete_user/<int:sno>")
@login_required
def delete_user(sno):
    link=session['my_var'].rpartition('/')
    link_route=link[len(link)-1]
    user = User.query.filter_by(sno=sno).first()
    # alltodo_of_user = Todo.query.filter(Todo.user==sno).all()
    Todo.query.filter_by(user=sno).delete()
    # db.session.delete(alltodo_of_user)
    db.session.delete(user)
    flash("User Deleted Successfully")
    db.session.commit()    
    return redirect("/"+link_route)



if __name__ == "__main__":
    app.run(debug=True, port=8000)
