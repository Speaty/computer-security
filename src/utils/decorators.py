import logging

from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user

LOGGER = logging.getLogger(__name__)

def logout_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            flash('You are already logged in.', 'info')
            return redirect(url_for('core.home'))
        return func(*args, **kwargs)
    return wrapper

def email_verification_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(current_user.is_confirmed)
        if not current_user.is_confirmed:
            flash('Please confirm your email.', 'warning')
            return redirect(url_for('accounts.inactive'))
        return func(*args, **kwargs)
    return wrapper

def check_is_2fa_enabled(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(current_user.is_two_factor_enabled)
        if not current_user.is_two_factor_enabled:
            flash('Please enable two factor authentication.', 'warning')
            return redirect(url_for('accounts.two_factor_setup'))

        return func(*args, **kwargs)
    return wrapper

