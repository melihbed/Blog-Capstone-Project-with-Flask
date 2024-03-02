from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, validators, PasswordField
from wtforms.validators import DataRequired, URL, InputRequired
from flask_ckeditor import CKEditorField
import email_validator


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = EmailField("Email", validators=[InputRequired("Please enter your email address."), validators.Email("Please enter your email.")])
    password = PasswordField("Password", validators=[InputRequired("Enter your password please!")])
    submit = SubmitField("Sign Me Up!")

# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment")
    submit = SubmitField("Submit Comment")