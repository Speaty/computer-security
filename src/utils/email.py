from flask_mail import Message 

from src import app, mail

def send_email(to, subject, html_body):
    print("send_email")
    msg = Message(
        subject, 
        recipients=[to],
        html=html_body,
        sender=app.config['MAIL_DEFAULT_SENDER'],
    )
    mail.send(msg)