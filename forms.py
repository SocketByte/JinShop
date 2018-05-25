from flask import session
from flask_wtf import RecaptchaField, FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_uploads import UploadSet, IMAGES
from wtforms import Form, StringField, PasswordField, validators, TextAreaField, IntegerField, SelectField

from microsms.microsms_conf import configuration


def get_register_form(form, captcha):
    class RegisterForm(Form):
        username = StringField('Name', [validators.Length(min=1, max=30), validators.DataRequired()])
        email = StringField('Email', [validators.DataRequired(), validators.Email()])
        password = PasswordField('Password', [
            validators.DataRequired(),
            validators.EqualTo('confirm_password', message="Passwords do not match")
        ])
        confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])
        if 'True' in captcha:
            recaptcha = RecaptchaField()
    return RegisterForm(form)


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


def get_shop_form(form):
    class SmsShopForm(Form):
        code = StringField('Response code', default=' ')
        if 'logged_in' in session:
            name = StringField('Minecraft name', [validators.DataRequired()], render_kw={'readonly': True})
        else:
            name = StringField('Minecraft name', [validators.DataRequired()])
        voucher = StringField('Voucher (optional)')
    return SmsShopForm(form)


def get_account_form(form):
    class AccountFormClass(Form):
        minecraft_name = StringField('Minecraft name', [
            validators.DataRequired(),
            validators.Length(max=16)
        ], default=session['minecraft_name'])

        email = StringField('Email', [validators.DataRequired(), validators.Email()],
                            default=session['email'])

        current_password = PasswordField('Current password')
        new_password = PasswordField('New password')

    return AccountFormClass(form)


choices = configuration['DROPDOWN']
class ServiceForm(FlaskForm):
    image = FileField('Image', [FileRequired(), FileAllowed(['png', 'jpg', 'jpeg'], 'You can upload only images!')])
    name = StringField('Name', [validators.DataRequired(), validators.Length(max=60)])
    id = StringField('Id', [validators.DataRequired(), validators.NoneOf(' '), validators.Length(max=60)])
    description = TextAreaField('Description', [validators.DataRequired(), validators.Length(min=10, max=400)])
    sms_number = SelectField('Price (PLN)', choices=choices, validators=[validators.DataRequired()])
    rewards = TextAreaField('Commands to execute after purchase', [validators.NoneOf('/')])

