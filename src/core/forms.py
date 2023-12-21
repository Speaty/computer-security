from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed

from wtforms import StringField, SubmitField, TextAreaField, FileField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp, EqualTo


class SubmissionForm(FlaskForm):
    subject = StringField('Subject', validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Subject"})
    contact_option = SelectField('Contact Option', choices=[('email', 'Email'), ('phone', 'Phone')], validators=[InputRequired()])
    submission = TextAreaField('Submission', 
                validators=[InputRequired(), Length(min=4, max=1000)], 
                render_kw={"placeholder": "Submission"})
    image = FileField('Image', 
                validators=[InputRequired(), 
                            FileAllowed(['jpg', 'png', 'jpeg'], '.jpg, .png, .jpeg files only!')],
                render_kw={"placeholder": "Image"})
    submit = SubmitField('Submit')

