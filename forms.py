from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")
    
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")
    
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment:", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
    
class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired()])
    phone_number = StringField("Phone Number", validators=[DataRequired()])
    message = CKEditorField("Message", validators=[DataRequired()])
    submit = SubmitField("SEND")
    
class RegisterForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired()], render_kw={"class": "form-control mb-6"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"class": "form-control mb-6"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"class": "form-control mb-6"})
    submit = SubmitField('Register')