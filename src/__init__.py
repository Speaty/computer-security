from decouple import config
import os
from cryptography.fernet import Fernet

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_security import Security, SQLAlchemyUserDatastore



app = Flask(__name__)
app_settings_value = os.environ.get('APP_SETTINGS')

app.config.from_object(app_settings_value)

# print(app.config)

cipher_suite = Fernet(config("ENCRYPTION_KEY"))


login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)



bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)

from src.accounts.views import accounts_bp
from src.core.views import core_bp
#inspect(accounts_bp, title="accounts_bp")
app.register_blueprint(accounts_bp)
app.register_blueprint(core_bp)




login_manager.login_view = 'accounts.login'
login_manager.login_message_category = 'danger'


from src.accounts.models import User, Role

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()




########################
#### error handlers ####
########################


@app.errorhandler(401)
def unauthorized_page(error):
    return render_template("errors/401.html"), 401


@app.errorhandler(404)
def page_not_found(error):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error_page(error):
    return render_template("errors/500.html"), 500