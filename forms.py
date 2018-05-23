from flask import session
from flask_wtf import RecaptchaField
from wtforms import Form, StringField, PasswordField, validators


class RegisterForm(Form):
    username = StringField('Name', [validators.Length(min=1, max=30), validators.DataRequired()])
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm_password', message="Passwords do not match")
    ])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])
    captcha = RecaptchaField('', [validators.DataRequired(message="Invalid captcha")])


class LoginForm(Form):
    username = StringField('Name', [validators.Length(min=1, max=30), validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])


class RecoveryForm(Form):
    username = StringField('Name', [validators.Length(min=1, max=30), validators.DataRequired()])


class PasswordChangeForm(Form):
    password = PasswordField('New password', [
        validators.DataRequired(),
        validators.EqualTo('confirm_password', message="Passwords do not match")
    ])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])


class SmsShopForm(Form):
    code = StringField('Response code', default=' ')
    name = StringField('Minecraft name', [validators.DataRequired()])
    voucher = StringField('Voucher (optional)')
