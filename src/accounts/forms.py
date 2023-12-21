from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError, Regexp, EqualTo

from src.accounts.models import User

class RegisterForm(FlaskForm):
    # username = StringField('Username', 
    #             validators=[InputRequired(), 
    #                         Length(min=4, max=80)],
    #             render_kw={"placeholder": "Username"})
    email = StringField('Email', 
                validators=[InputRequired(), Email(message='Invalid email'), Length(max=120)], 
                render_kw={"placeholder": "Email"})
    name = StringField('Name',
                validators=[InputRequired(), Length(min=4, max=80)],
                render_kw={"placeholder": "Name"})
    phone = StringField('Phone',
                validators=[InputRequired(), Length(min=11, max=11)],
                render_kw={"placeholder": "Phone"})
    password = PasswordField('Password', 
                validators=[InputRequired(), Length(min=8, max=80),
                            Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+])', 
                                   message='Password must have at least one lowercase letter, one uppercase letter, one digit, and one special character')
                            ], 
                render_kw={"placeholder": "Password"})
    confirm = PasswordField('Confirm Password', 
                validators=[InputRequired(),
                            EqualTo('password', message='Passwords must match'),
                            Length(min=8, max=80)], 
                render_kw={"placeholder": "Confirm Password"})

    


    submit = SubmitField('Register')

        
    def validate_email(self, email):
        # print(email)
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        
        if existing_user_email:
            raise ValidationError(
                'That email is taken. Please choose a different one.')
    def validate_phone(self, phone):
        # print(phone)
        existing_user_phone = User.query.filter_by(
            phone=phone.data).first()
        
        if existing_user_phone:
            raise ValidationError(
                'That phone is taken. Please choose a different one.')



        
class LoginForm(FlaskForm):
    email = StringField('Email', 
                validators=[InputRequired(), Length(min=4, max=80)], 
                render_kw={"placeholder": "Email"})
    password = PasswordField('Password', 
                validators=[InputRequired(), Length(min=8, max=80)], 
                render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')



class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password',
                validators=[InputRequired(), Length(min=8, max=80)],
                render_kw={"placeholder": "Current Password"})
    new_password = PasswordField('New Password',
                validators=[InputRequired(), Length(min=8, max=80),
                            Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+])',
                                   message='Password must have at least one lowercase letter, one uppercase letter, one digit, and one special character')
                            ],
                render_kw={"placeholder": "New Password"})
    confirm = PasswordField('Confirm Password',
                validators=[InputRequired(),
                            EqualTo('new_password', message='Passwords must match'),
                            Length(min=8, max=80)],
                render_kw={"placeholder": "Confirm Password"})



class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', 
                validators=[InputRequired(), Length(min=4, max=80)], 
                render_kw={"placeholder": "Email"})
    submit = SubmitField('Reset Password')


        
class ResetForgotPasswordForm(FlaskForm):
    password = PasswordField('Password', 
                validators=[InputRequired(), Length(min=8, max=80),
                            Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+])', 
                                   message='Password must have at least one lowercase letter, one uppercase letter, one digit, and one special character')
                            ], 
                render_kw={"placeholder": "Password"})
    confirm = PasswordField('Confirm Password', 
                validators=[InputRequired(),
                            EqualTo('password', message='Passwords must match'),
                            Length(min=8, max=80)], 
                render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField('Reset Password')


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[InputRequired(), Length(min=6, max=6)])
