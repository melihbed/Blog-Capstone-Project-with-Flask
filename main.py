from datetime import date
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, mapped_column
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from admin_decorator import admin_only
# Relational Database Libraries
from typing import List

from sqlalchemy import ForeignKey
from sqlalchemy import Integer, Text, String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import relationship
# Gravatar
from flask_gravatar import Gravatar


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# For user's avatars
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    """
    This callback is used to reload the user object from the user ID store
    :param user_id: ID of a user
    :return: the corresponding user object
    """
    return db.get_or_404(User, user_id)

# CONFIGURE TABLES
# TODO: Create a User table for all your registered users. (Parent)
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)

    # TODO: The db.relationship in the User model establishes a one-to-many relationship with the BlogPost and Comment model
    blogposts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # TODO: Create Foreign Key, "users.id" the users refers to the tablename of User
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # TODO: Create reference to the User object. The "posts" refers to the tablename of User
    author = relationship("User", back_populates="blogposts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    #***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_blogpost")

# Adding a Table for Comments
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # TODO: Create Foreign Key, "users.id" the users refers to the tablename of User
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # TODO: Create reference to the User object.
    comment_author = relationship("User", back_populates="comments")
    #***************Child Relationship*************#
    blogpost_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_blogpost = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    """
    Register a new user.

    This function handles the registration process for a new user. It validates the registration form,
    checks if the user already exists in the database, hashes and salts the password, adds the user data
    to the database, and logs in the user.

    Returns:
        redirect: Redirects the user to the home page after successful registration.
        render_template: Renders the registration form template for GET requests.

    """
    form = RegisterForm()
    if form.validate_on_submit():
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if the user is already in the database
        user_check = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # If user already exists in the database, emind them about account existence
        if user_check:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        # hashing and salting the password
        hashed_salted_password = generate_password_hash(password=password,
                                                        method="pbkdf2:sha256",
                                                        salt_length=8)
        # Adding the user data to our database and commit the changes
        new_user = User(
            username=username,
            email=email,
            password=hashed_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        # When users successfully register they are taken back to the home page and are logged in with Flask-Login.
        login_user(new_user)

        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email.
def get_user_by_email(email):
    user = db.session.query(User).filter_by(email=email).first()
    return user

@app.route('/login', methods=["GET", "POST"])
def login():
    """
    Handles the login functionality of the web application.

    This function receives a POST request with the user's login credentials,
    validates the form data, checks if the username exists in the database,
    verifies the password, and authenticates the user if the credentials are correct.

    Returns:
        If the login is successful, redirects the user to the "get_all_posts" route.
        If the login fails, redirects the user back to the login page with appropriate error messages.

    """
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        print("username:", username)

        # Find the user by his/her username
        user = db.session.execute(db.select(User).where(User.username == username)).scalar()
        print("user:", user)
        # if username doesn't exist in the database
        if not user:
            flash("That username doesn't exist, please try again.")
            return redirect(url_for('login'))
        # Check stored password hash against entered password hash
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash("Password is incorrect, access denied!")
            return redirect(url_for("login"))
        # If it matches, authenticate the user
        else:
            login_user(user)
            # Redirect to the target route successfully
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form, logged_in=False)


@app.route('/logout')
def logout():
    """
    Logs out the current user.
    """
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    # Only allow logged-in users to comment on posts
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment!")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=comment_form.comment.data,
            comment_author=current_user,
            parent_blogpost=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, commentF=comment_form, current_user=current_user)

# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
