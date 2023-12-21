from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename


import uuid
from rich import inspect

from src import db
from src.core.forms import SubmissionForm
from src.core.models import UserSubmission
from src.accounts.models import User
from src.utils.decorators import email_verification_required, check_is_2fa_enabled
from src.utils.image import is_valid_image, is_less_than_max_file_size

core_bp = Blueprint('core', __name__, template_folder='templates/core')

@core_bp.route('/')
def home():
    return render_template('core/index.html')


@core_bp.route('/app')
@login_required
@email_verification_required
@check_is_2fa_enabled
def app():
    form = SubmissionForm()
    if current_user.is_authenticated:
        user_submissions = UserSubmission.query.filter_by(user_id=current_user.id).all()
        return render_template('core/dashboard.html', user_submissions=user_submissions, form=form)

    return render_template('core/dashboard.html', form=form)


@core_bp.route('/admin-dashboard')
@login_required
def admin_dashboard():
    user_submissions = UserSubmission.query.all()
    submissions_with_user_info = []

    for submission in user_submissions:
        user_info = next((user for user in User.query.all() if user.id == submission.user_id), None)
        if user_info:
      
            submissions_with_user_info.append({
                'subject': submission.subject,
                'content': submission.submission,
                'filename': submission.filename,
                'created_on': submission.created_on,
                'user_name': user_info.name,
                'user_email': user_info.email,
                'user_phone': user_info.phone,
                'contact': submission.contact
            })
    sorted_submissions = sorted(submissions_with_user_info, key=lambda k: k['created_on'], reverse=True)
    if not current_user.is_admin:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('core.home'))
    return render_template('core/admin_dashboard.html', user_submissions=sorted_submissions)

@core_bp.route('/submission', methods=['POST'])
@login_required
@email_verification_required
@check_is_2fa_enabled
def submission():
    form = SubmissionForm()
    
    if form.validate_on_submit():
        inspect(form.image.data)
        image = form.image.data

        if not is_valid_image(image):
            flash('Invalid file type. Only jpg, jpeg, and png files are allowed.', 'danger')
        elif not is_less_than_max_file_size(image):
            flash('File size is too large. Max file size is 5MB.', 'danger')
        else:
            filename =  str(uuid.uuid4()) + '-' + secure_filename(form.image.data.filename) 
            inspect(form.image.data)
            file = request.files['image']
            
            file.save(current_app.config['UPLOAD_FOLDER'] + filename)

            # img = Image.open(form.image.data)
            # img.show()

            user_submission = UserSubmission(user_id=current_user.id, subject=form.subject.data, submission=form.submission.data, filename=filename, contact=form.contact_option.data)
            db.session.add(user_submission)
            db.session.commit()
            flash('Your submission has been saved.', 'success')
            return redirect(url_for('core.app'))
    return render_template('core/dashboard.html', form=form)