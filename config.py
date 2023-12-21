from decouple import config
DATABASE_URI = config("DATABASE_URL")


class Config(object):
    APP_NAME = "LOVEJOY"
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = config("SECRET_KEY", default="guess-me")
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SECURITY_PASSWORD_SALT = config("SECURITY_PASSWORD_SALT", default="guess-me")
    ENCRYPTION_KEY  = b'IitSGaPuInErC5cUTSOJ-vA0xOOHR-xLuCEDl9dTcKk='
    UPLOAD_FOLDER = config("UPLOAD_FOLDER")

    # mail settings
    MAIL_DEFAULT_SENDER = config("MAIL_DEFAULT_SENDER", default="js2042@sussex.ac.uk")
    MAIL_SERVER = config("MAIL_SERVER", default="smtp.gmail.com")
    MAIL_PORT = config("MAIL_PORT", default=587, cast=int)
    MAIL_USE_TLS = config("MAIL_USE_TLS", default=True, cast=bool)
    MAIL_USE_SSL = config("MAIL_USE_SSL", default=False, cast=bool)
    MAIL_USERNAME = config("EMAIL_USER")
    MAIL_PASSWORD = config("EMAIL_PASS")

    # capcha settings
    RECAPTCHA_ENABLED = True
    RECAPTCHA3_PUBLIC_KEY = config("RECAPTCHA_SITE_KEY")
    RECAPTCHA3_PRIVATE_KEY = config("RECAPTCHA_SECRET_KEY")
    RECAPTCHA_THEME = "dark"
    RECAPTCHA_TYPE = "image"
    RECAPTCHA_SIZE = "normal"
    RECAPTCHA_LANGUAGE = "en"
    RECAPTCHA_RTABINDEX = 10
    RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"




class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    DEBUG_TB_ENABLED = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///testdb.sqlite"
    BCRYPT_LOG_ROUNDS = 1
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
    DEBUG_TB_ENABLED = False

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # # log to stderr
        # import logging
        # from logging import StreamHandler

        # file_handler = StreamHandler()
        # file_handler.setLevel(logging.INFO)
        # app.logger.addHandler(file_handler)