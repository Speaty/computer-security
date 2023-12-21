from datetime import datetime
import requests
from rich import inspect

from flask import Blueprint, render_template, redirect, url_for, flash, current_app, request
from flask_login import login_required, current_user, logout_user, login_user

from src import bcrypt, db, cipher_suite

from src.accounts.forms import ChangePasswordForm, ResetForgotPasswordForm, RegisterForm, LoginForm, TwoFactorForm, ForgotPasswordForm
from src.accounts.models import User, PasswordChanges, encrypt_data, decrypt_data
from src.utils.decorators import logout_required
from src.utils.email import send_email
from src.utils.two_factor import getb64encoded_qr_image
from src.accounts.token import generate_token, confirm_token

accounts_bp = Blueprint('accounts', __name__, template_folder='templates/accounts/')

@accounts_bp.route('/login', methods=['GET', 'POST'])
@logout_required
def login():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already logged in.", "info")
            return redirect(url_for('core.app'))
        else:
            flash("You have not enabled 2-Factor Authentication. Please enable first to login.", "info")
            return redirect(url_for('accounts.two_factor_setup'))

    form = LoginForm()

    if form.validate_on_submit():
        users = User.query.all()
        # Loop through the users and print the _email values
        for user in users:
            # print(user.email)
            if user.email == form.email.data:
   
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    if not current_user.is_two_factor_enabled:
                        flash("You have not enabled 2-Factor Authentication. Please enable first to login.", "info")
                        return redirect(url_for('accounts.two_factor_setup'))
                    return redirect(url_for('accounts.two_factor_verify'))
                else:
                    flash('Invalid username or password', 'danger')
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('/accounts/login.html', form=form)


def authenticate_recaptcha(form):
    secret_response = request.form.get('g-recaptcha-response')
    verify_response = requests.post(url =f'{current_app.config["RECAPTCHA_VERIFY_URL"]}?secret={current_app.config["RECAPTCHA3_PRIVATE_KEY"]}&response={secret_response}')
    
    print(verify_response.json())
    
    if verify_response.json()['success']:
        return True
    else:
        return False


@accounts_bp.route('/register', methods=['GET', 'POST'])
@logout_required
def register():
    if current_user.is_authenticated:
        if current_user.is_two_factor_enabled:
            flash('You have already enabled two factor authentication.', 'success')
            return redirect(url_for('core.app'))
        else:
            flash('You must have 2-Factor Authentication enabled before you can access the site', 'warning')
            return redirect(url_for('accounts.two_factor_setup'))
    
    
    form = RegisterForm()
    
    if form.validate_on_submit():

        try:
            if not authenticate_recaptcha(form):
                flash('Please check the captcha', 'danger')
                return redirect(url_for('accounts.register'))
            inspect(form)
            user = User(
                email=form.email.data,
                password=form.password.data,
                phone=form.phone.data,
                name=form.name.data
            )
            # inspect(user)
            db.session.add(user)
            db.session.commit()

            token = generate_token(user.email)
            confirm_url = url_for('accounts.confirm_email', token=token, _external=True)
            html = render_template('/accounts/confirm_email.html', confirm_url=confirm_url)
            subject = "Welcome to Lovejoy's Antique Evaluations! Confirm your email"
            send_email(user.email, subject, html)

            login_user(user)
            flash('A confirmation email has been sent via email.', 'success')
        
            return redirect(url_for('accounts.inactive'))
        except Exception as e:
            db.session.rollback()
            print(e)
            flash('There was a problem creating your account.', 'danger')


    return render_template('/accounts/register.html', form=form, reCAPTCHA_site_key = current_app.config['RECAPTCHA3_PUBLIC_KEY'])

@accounts_bp.route('/confirm/<token>')
@login_required
def confirm_email(token):
    if current_user.is_confirmed:
        flash('Account already confirmed. Please login.', 'success')
        return redirect(url_for('core.app'))
    email = confirm_token(token)
    # print(email)
    # print(current_user._email)
    # print(encrypt_data(email))
    # print(current_user.email == email)
    # print(current_user._email == encrypt_data(email))

    try:

    # Perform actions with the user object as needed
    # except Exception as e:
        # Handle the case where no user is found
        users = User.query.all()
        # Loop through the users and print the _email values
        for user in users:
            # print(user.email)
            if user.email == email:
                # print('HERE')
                user.is_confirmed = True
                user.confirmed_on = datetime.now()
                db.session.add(user)
                db.session.commit()
                flash('You have confirmed your account. Thanks!', 'success')
        print("User not found.")
    # user = User.query.filter_by(email=email).first_or_404()
    # if user.email == email:
    #     user.is_confirmed = True
    #     user.confirmed_on = datetime.now()
    #     db.session.add(user)
    #     db.session.commit()
    #     flash('You have confirmed your account. Thanks!', 'success')   
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('core.app'))

@accounts_bp.route('/inactive')
@login_required
def inactive():
    if current_user.is_confirmed and current_user.is_two_factor_enabled:
        return redirect(url_for('core.app'))
    elif current_user.is_confirmed and not current_user.is_two_factor_enabled:
        flash('Please enable two factor authentication.', 'warning')
        return redirect(url_for('accounts.two_factor_setup'))
    else:
        flash('Please confirm your account!', 'warning')
        return render_template('/accounts/inactive.html')

@accounts_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('accounts.login'))
                    

@accounts_bp.route('/resend')
@login_required
def resend_confirmation():
    if current_user.is_confirmed:
        flash('Your account has already been confirmed.', 'success')
        return redirect(url_for('core.home'))
    token = generate_token(current_user.email)
    confirm_url = url_for('accounts.confirm_email', token=token, _external=True)
    html = render_template('/accounts/confirm_email.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('accounts.inactive'))


@accounts_bp.route('/two_factor_setup', methods=['GET', 'POST'])
@login_required
def two_factor_setup():
    if current_user.is_two_factor_enabled:
        flash('Two factor authentication is already enabled for your account.', 'success')
        return redirect(url_for('core.app'))
    secret = current_user.secret_token
    uri = current_user.get_auth_uri()
    base64_qr_image = getb64encoded_qr_image(uri)
    return render_template('/accounts/two_factor_setup.html', secret=secret, qr=base64_qr_image)

@accounts_bp.route('/two_factor_verify', methods=['GET', 'POST'])
@login_required
def two_factor_verify():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.verify_totp(form.otp.data):
            if current_user.is_two_factor_enabled:
                flash('Two factor authentication is already enabled for your account.', 'success')
                return redirect(url_for('core.app'))
            else:
                try:
                    print('HERE')
                    current_user.is_two_factor_enabled = True
                    db.session.commit()
                    flash('Two factor authentication has been enabled.', 'success')
                    return redirect(url_for('core.app'))
                except Exception as e:
                    db.session.rollback()
                    flash('There was a problem enabling two factor authentication.', 'danger')
                    return redirect(url_for('accounts.two_factor_verify'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('accounts.two_factor_verify'))
    # else:
    #     if not current_user.is_two_factor_enabled:
    #         flash('You must have 2-Factor Authentication enabled before you can access the site', 'warning')
    #         return redirect(url_for('accounts.two_factor_setup'))
    
    return render_template('/accounts/two_factor_verify.html', form=form)

@accounts_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    return render_template('/accounts/settings.html')


@accounts_bp.route('/settings/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.current_password.data):
            current_user.password = bcrypt.generate_password_hash(form.new_password.data)
            db.session.add(current_user)
            db.session.commit()
            flash('Password has been changed.', 'success')
            return redirect(url_for('accounts.settings'))
        else:
            flash('Invalid current password.', 'danger')
            return redirect(url_for('accounts.change_password'))

    return render_template('/accounts/change_password.html', form=form)

@accounts_bp.route('/settings/forgot_password', methods=['GET', 'POST'])
@logout_required
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        try:
            users = User.query.all()
            for user in users:
                # print('db', user.email)
                # print('form', form.email.data)
                if user.email == form.email.data:
                    # print('match', user.email, form.email.data)
                    token = generate_token(user.email)
                    confirm_url = url_for('accounts.reset_password', token=token, _external=True)
                    html = render_template('/accounts/reset_password_email.html', confirm_url=confirm_url)
                    subject = "Lovejoy's Antique Evaluations - Reset Password Request"
                    send_email(user.email, subject, html)
                    flash('If an account exists, a password reset email will have been sent.', 'success')
                    return redirect(url_for('core.home'))
        except Exception as e:
            flash('If an account exists, a password reset email will have been sent', 'success')
            return redirect(url_for('core.home'))
    return render_template('/accounts/forgot_password.html', form=form)

@accounts_bp.route('/settings/forgot_password/<token>', methods=['GET', 'POST'])
@logout_required
def reset_password(token):
    form = ResetForgotPasswordForm()

    email = confirm_token(token)

    users = User.query.all()
        # Loop through the users and print the _email values
    try:
        for user in users:
            # print(user.email)
            # print(email)
            if user.email == email:
                # print('HERE')

                if form.validate_on_submit():
                    try:
                        user.password = bcrypt.generate_password_hash(form.password.data)
                        pass_change_log = PasswordChanges(user_id=user.id, changed_on=datetime.now())
                        db.session.add(user)
                        db.session.add(pass_change_log)
                        db.session.commit()
                        flash('Password has been reset.', 'success')
                        return redirect(url_for('accounts.login'))
                    except Exception as e:
                        db.session.rollback()
                        flash('There was a problem changing your password.', 'danger')
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('core.home'))

    return render_template('/accounts/reset_forgotten_password.html', form=form)


