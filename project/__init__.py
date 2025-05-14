from datetime import timedelta
from flask import Flask, session, request, redirect, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask import g
from flask_session import Session
from flask_mail import Mail
import os
from helpers import generate_sitemap
from dotenv import load_dotenv
import logging


db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()


def create_app():
    app = Flask(__name__)

    load_dotenv()

    app.jinja_env.globals.update(generate_sitemap = generate_sitemap)

    # app.config['MYSQL_HOST'] = os.getenv('mysql_host')
    # app.config['MYSQL_USER'] = os.getenv('mysql_user')
    # app.config['MYSQL_PASSWORD'] = os.getenv('mysql_password')
    # app.config['MYSQL_DB'] = os.getenv('mysql_db')

    # app.config['POSTGRES_HOST'] = os.getenv('postgres_host')
    # app.config['POSTGRES_USER'] = os.getenv('postgres_user')
    # app.config['POSTGRES_PASSWORD'] = os.getenv('postgres_password')
    # app.config['POSTGRES_DB'] = os.getenv('postgres_db')

    app.config['SECRET_KEY'] = os.getenv('secret_key')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SESSION_COOKIE_SECURE'] = True
    #app.config['SESSION_COOKIE_NAME'] = 'my_session_cookie'
    app.config['TIMEOUT'] = 300 # seconds
    Session(app)

    # Mail config settings:
    app.config['MAIL_SERVER']='live.smtp.mailtrap.io'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USERNAME'] = 'api'
    app.config['MAIL_PASSWORD'] = os.getenv('mail_password')
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False

    # LEGACY MYSQL
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://' + os.getenv('mysql_user') + \
    #     ':' + os.getenv('mysql_password') + '@' + os.getenv('mysql_host') + '/' + os.getenv('mysql_db')
    
    # Get environment variables with default empty strings to prevent None values
    postgres_user = os.getenv('postgres_user', '')
    postgres_password = os.getenv('postgres_password', '')
    postgres_host = os.getenv('postgres_host', '')
    postgres_db = os.getenv('postgres_db', '')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f'postgresql+psycopg2://{postgres_user}:{postgres_password}@{postgres_host}/{postgres_db}'
    )

    app.config['SQLALCHEMY_POOL_SIZE'] = 5
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 450
    app.config['SQLALCHEMY_MAX_OVERFLOW'] = 2
    app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,  # enable connection pool pre-ping
    }

    db.init_app(app)
    mail.init_app(app)


    with app.app_context():

        from .views import views
        # from .blog import blog
        # from .contact import contact_bp
        # from .auth import auth_bp
        from .models import supplier_login, admin_login

        app.register_blueprint(views, url_prefix="/")
        # app.register_blueprint(blog, url_prefix="/blog")
        # app.register_blueprint(contact_bp, url_prefix="/contact")
        # app.register_blueprint(auth_bp, url_prefix="/auth")

        db.create_all()

        # Configure login manager with proper typing
        login_manager.init_app(app)
        # Use dictionary-style access for Flask-Login 0.6.3+ compatibility
        login_manager.__dict__['login_view'] = "views.login_vendor"
        login_manager.__dict__['login_message'] = ""
        login_manager.__dict__['login_message_category'] = "error"

        @login_manager.user_loader
        def load_user(id):
            user_type = session.get('user_type')
            if user_type == 'supplier':
                user = supplier_login.query.filter_by(id = id).first()
            elif user_type == 'admin':
                user = admin_login.query.filter_by(id = id).first()
            else:
                user = None
            return user

        @app.before_request
        def before_request():
            # Initialize user_type if it doesn't exist
            if 'user_type' not in session:
                session['user_type'] = None
            
            # Handle HTTPS redirect
            if not request.is_secure and request.host != 'localhost:2000':
                return redirect(request.url.replace('http://', 'https://'), code=301)

        def handle_error(error):
            error_code = getattr(error, 'code', 500)  # Get the error code, default to 500
            return render_template('error.html', error_code=error_code), error_code

        app.register_error_handler(404, handle_error)
        app.register_error_handler(500, handle_error)
        app.register_error_handler(400, handle_error)
        app.register_error_handler(403, handle_error)
        app.register_error_handler(401, handle_error)
        app.register_error_handler(405, handle_error)
        app.register_error_handler(503, handle_error)

        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

        return app
