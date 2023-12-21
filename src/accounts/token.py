from itsdangerous import URLSafeTimedSerializer

from src import app

def generate_token(email):
    print("generate_token -------------------------- " + email)
    serialiser = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    print(serialiser.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT']))
    return serialiser.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serialiser = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serialiser.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except:
        return False