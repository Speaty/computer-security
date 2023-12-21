import getpass
import unittest
from datetime import datetime

from flask.cli import FlaskGroup

from src import app, db
from src.accounts.models import User

cli = FlaskGroup(app)


@cli.command("test")
def test():
    """Runs the unit tests without coverage."""
    tests = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    else:
        return 1


@cli.command("create_admin")
def create_admin():
    """Creates the admin user."""
    email = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Enter password again: ")
    if password != confirm_password:
        print("Passwords don't match")
        return 1
    try:
        user = User(
                    email=email, 
                    password=password,
                    name="admin",
                    phone="12345678901", 
                    is_admin=True,
                    is_confirmed=True,
                    confirmed_on=datetime.now())
        db.session.add(user)
        db.session.commit()
        print(f"Admin with email {email} created successfully!")
    except Exception:
        print("Couldn't create admin user.")

@cli.command("db")
def db():
    """Runs the migrations."""
    db.create_all()


if __name__ == "__main__":
    cli()