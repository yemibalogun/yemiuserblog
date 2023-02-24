from flask import Flask, render_template, redirect, url_for, flash, get_flashed_messages, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, CommentForm, ContactForm, RegisterForm
from flask_gravatar import Gravatar
from datetime import datetime 
import hashlib


current_year = datetime.now().year

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=True, base_url=None)

def md5(value):
    return hashlib.md5(value.encode('utf-8')).hexdigest()

app.jinja_env.filters['md5'] = md5


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLES

class User(db.Model, UserMixin):
    __tablename__= "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    posts = db.relationship('BlogPost', backref='user', lazy=True)
    comments = db.relationship('Comment', back_populates='comment_author')
    
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")
    
    
class Comment(db.Model):
    __tablename__="comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_author = relationship('User', back_populates="comments")
    
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    
class Contact(db.Model):
    __tablename__="contacts"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    phone_number = db.Column(db.String, nullable=False)
    message = db.Column(db.String, nullable=False)
    date = db.Column(db.Date, default=datetime.today().strftime('%d-%b-%Y'))
    
with app.app_context():
    db.create_all()
    
def admin_only(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        # Check if user is an admin
        if not is_admin():
            return redirect(url_for('error_page'))
        # Call the actual view function if the user is an admin 
        return view_func(*args, **kwargs)
    return decorated_view

# Define a protected route that requires admin access
@app.route('/admin')
@admin_only
def admin_page():
    return 'Admin Page'

# Define an error page that will be displayed if the user is not an admin 
@app.route('/error')   
def error_page():
    return abort(403) 

# A function to check if the user is an admin
def is_admin():
    # Replace this with your own logic to check if the user is an admin 
    return True


@app.route('/')
def get_all_posts():
    
    posts = BlogPost.query.all()
    
    return render_template("index.html", all_posts=posts, year=current_year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    messages = get_flashed_messages()
    
    if form.validate_on_submit():
        password = form.password.data
        hashed_password = generate_password_hash(password)
        email = form.email.data
        username = form.username.data
        
        new_user = User(
            username = username,
            email = email,
            password = hashed_password
        )
        
        if not db.session.query(User).filter_by(email=email).first(): 
            db.session.add(new_user)
            db.session.commit()
        
        #This line will authenticate the user with Flask-Login
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("This email already exists, please log in instead!")
            return redirect(url_for('login'))
    
    return render_template("register.html", form=form, messages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    messages = get_flashed_messages()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = db.session.query(User).filter_by(email=email).first()
        if not user:    
        # Email doesn't exist
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrent
            
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
            
    return render_template("login.html", form=form, year=current_year, messages=messages)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        
            
        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=requested_post.id))
        
        
        
    return render_template("post.html", post=requested_post, form=form, current_user=current_user, year=current_year)


@app.route("/about")
def about():
    return render_template("about.html", year=current_year)


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        new_message = Contact(
            name=form.name.data,
            email=form.email.data,
           phone_number=form.phone_number.data,
           message=form.message.data
        )
        
        db.session.add(new_message)
        db.session.commit()
    
        
    return render_template("contact.html", form=form, year=current_year)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if current_user.is_authenticated:
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.username,
                author_id=current_user.id,
                date=date.today().strftime("%B %d, %Y")
            )
            new_post.user_id = current_user.id
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    else:
        flash('You are not logged in.')
        return redirect(url_for('login'))
    
    return render_template("make-post.html", form=form, year=current_year)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
