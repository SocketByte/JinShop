import configparser
import hashlib

import mcrcon
from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from forms import LoginForm, RecoveryForm, PasswordChangeForm, get_account_form, get_shop_form, \
    get_register_form
from heads import HeadManager
from microsms.microsms import check_code
from microsms.microsms_conf import configuration
from sendmail import send_recovery_email
from util import vig
from util.randomstring import generate_random
from util.util import authorized, get_epoch_time

# Create default configuration file
config = configparser.ConfigParser()
config['Key'] = {
    'recaptcha_public_key': 'your recaptcha public key',
    'recaptcha_private_key': 'your recaptcha private key',
}
config['Rcon'] = {
    'minecraft_rcon_host': 'localhost',
    'minecraft_rcon_port': 25575,
    'minecraft_rcon_password': 'rcon_password'
}
config['App'] = {
    'address': 'localhost',
    'port': 5000,
    'secret_key': 'your session secret key',
    'database_uri': 'mysql://root@localhost/minecraftshop?',
    'captcha': False
}
config['Permissions'] = {
    'admins': 'SocketByte,SomeoneElse'
}
with open('configuration.ini', 'w') as configfile:
    config.write(configfile)

# Change that to configuration.ini!
config.read('secret_conf.ini')  # Debug file for testing purposes

admins = config['Permissions']['admins'].split(',')

# Global variables
# Recaptcha keys
recaptcha_public_key = config['Key']['recaptcha_public_key']
recaptcha_private_key = config['Key']['recaptcha_private_key']
# Minecraft RCON configuration
minecraft_rcon_host = config['Rcon']['minecraft_rcon_host']
minecraft_rcon_port = config['Rcon']['minecraft_rcon_port']
minecraft_rcon_password = config['Rcon']['minecraft_rcon_password']
# App configuration
app_address = config['App']['address']
app_port = config['App']['port']

# Create Flask instance
app = Flask(__name__, static_url_path='/static')
app.secret_key = config['App']['secret_key']
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = config['App']['database_uri']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = recaptcha_public_key
app.config['RECAPTCHA_PRIVATE_KEY'] = recaptcha_private_key

# Connect to the database and create tables
database = SQLAlchemy(app)

# Create MCRcon instance and connect to minecraft server
rcon = mcrcon.MCRcon(minecraft_rcon_host,
                     minecraft_rcon_password,
                     int(minecraft_rcon_port))
rcon.connect()

# Create bCrypt instance
bcrypt = Bcrypt(app)

# Create head manager for last buyers
heads = HeadManager()


# Database models
class Account(database.Model):
    __tablename__ = "accounts"

    id = database.Column('id', database.Integer, autoincrement=True, primary_key=True)
    name = database.Column('username', database.String(30), nullable=False, unique=True)
    minecraft_name = database.Column('mc_name', database.String(16), nullable=False, unique=False)
    email = database.Column('email', database.String(30), nullable=False, unique=True)
    password = database.Column('password', database.String(100), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


class RecoveryData(database.Model):
    __tablename__ = "recovery_data"

    secret_key = database.Column('secret_key', database.String(100), nullable=False, primary_key=True)
    name = database.Column('username', database.String(30), nullable=False, unique=True)
    email = database.Column('email', database.String(30), nullable=False, unique=True)
    exp_time = database.Column('exp_time', database.BIGINT, nullable=False)

    def __init__(self, name, email):
        self.name = name
        self.email = email
        self.exp_time = get_epoch_time() + (30 * 60 * 1000)  # 30 minutes
        self.secret_key = str(hashlib.sha256(bytes(generate_random(32), 'utf-8')).hexdigest())

    def is_valid(self):
        return get_epoch_time() < self.exp_time

    def get_unique_link(self):
        return "http://" + app_address + ":" + str(app_port) + "/recover/" + self.secret_key


class ShopData(database.Model):
    __tablename__ = "shop_data"

    id = database.Column('id', database.String(60), nullable=False, primary_key=True, unique=True)
    image = database.Column('image', database.String(60), nullable=False)
    name = database.Column('name', database.String(60), nullable=False)
    description = database.Column('description', database.Text)
    sms = database.Column('sms_number', database.Integer)
    rewards = database.Column('reward_command', database.Text)

    def __init__(self, id, name, description, *rewards):
        self.id = id
        self.name = name
        self.description = description
        builder = ""
        for reward in rewards:
            builder.join(';' + reward)
        self.rewards = builder.replace(';', '', 1)


class Voucher(database.Model):
    __tablename__ = "vouchers"

    id = database.Column('id', database.Integer, nullable=False, primary_key=True, autoincrement=True)
    key = database.Column('key', database.String(60), nullable=False, unique=True)
    offer = database.Column('offer_id', database.String(60), nullable=False)
    uses = database.Column('uses', database.Integer, nullable=False, default=1)


database.create_all()


# Other models
class PanelModel(object):
    def __init__(self, account_form):
        self.account_form = account_form


# Query all shop_offers from SQL and add test one if no offers available.
shop_offers = ShopData.query.all()

if len(shop_offers) == 0:
    data = ShopData('default', 'Default Shop Item',
                    'Default shop item to populate shop area')
    data.sms = configuration['REQUESTS'][1]
    data.image = '/static/images/logo.png'
    database.session.add(data)
    database.session.commit()
    app.shop_offers = ShopData.query.all()


@app.route('/register', methods=['GET', 'POST'])
def register():
    captcha = config['App']['captcha']
    form = get_register_form(request.form, captcha)
    if form.validate_on_submit():
        name = form.data['username']
        email = form.data['email']

        query_name = Account.query.filter_by(name=name).first()
        query_email = Account.query.filter_by(email=name).first()
        if query_name or query_email is not None:
            flash("There's already someone with that nickname or email!", 'danger')
            return render_template('views/register.html', form=form, captcha=captcha)

        password = bcrypt.generate_password_hash(form.data['password'])

        account = Account(name, email, password)
        account.minecraft_name = name
        database.session.add(account)
        database.session.commit()

        flash('You are now registered!', 'success')
        return redirect(url_for('home'))

    return render_template('views/register.html', form=form, captcha=captcha)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.data['username']
        password = form.data['password']

        account = Account.query.filter_by(name=name).first()
        if account is not None:
            if bcrypt.check_password_hash(account.password, password):
                session['logged_in'] = True
                session['username'] = name
                session['email'] = account.email
                session['minecraft_name'] = account.minecraft_name

                flash("You're now logged in!", 'success')
                return redirect(url_for('panel'))
            else:
                flash('Wrong password', 'danger')
        else:
            flash('No account registered for that user', 'danger')
    return render_template('views/login.html', form=form)


# password recovery
@app.route('/recovery', methods=['GET', 'POST'])
def recovery():
    form = RecoveryForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.data['username']

        account = Account.query.filter_by(name=name).first()
        if account is not None:
            email = account.email

            recovery_data = RecoveryData(name, email)
            database.session.add(recovery_data)
            database.session.commit()

            send_recovery_email("do_not_respond@testflaskapp.com", email, recovery_data.get_unique_link())

            flash('Your password recovery link was sent to ' + email, 'success')
            return redirect(url_for('login'))
        else:
            flash('No user with that username', 'danger')
            return render_template('views/recovery.html', form=form)

    return render_template('views/recovery.html', form=form)


@app.route('/recover/<secret_key>', methods=['GET', 'POST'])
def recover(secret_key):
    form = PasswordChangeForm(request.form)
    data = RecoveryData.query.filter_by(secret_key=secret_key).first()
    if data is None:
        flash('Secret key for password recovery was invalid', 'danger')
        return redirect(url_for('home'))

    if not data.is_valid():
        flash('This recovery link has expired.')
        database.session.delete(data)
        database.session.commit()
        return redirect(url_for('home'))

    if request.method == 'POST' and form.validate():
        account = Account.query.filter_by(name=data.name, email=data.email).first()
        if account is None:
            flash('Something went wrong, unknown user', 'danger')
            return redirect(url_for('home'))

        account.password = bcrypt.generate_password_hash(form.data['password'])
        database.session.delete(data)
        database.session.commit()

        flash('Successfully changed your password', 'success')
        return redirect(url_for('login'))

    return render_template('views/recover.html', form=form)


# Control Panel Routes
@app.route('/panel')
@authorized
def panel():
    return redirect(url_for('panel_account'))


@app.route('/panel/account', methods=['GET', 'POST'])
@authorized
def panel_account():
    form = get_account_form(request.form)
    if request.method == 'POST' and form.validate():
        account = Account.query.filter_by(name=session['username'], email=session['email']).first()
        changed = False
        if form.data['minecraft_name'] != session['minecraft_name']:
            account.minecraft_name = form.data['minecraft_name']
            session['minecraft_name'] = account.minecraft_name
            changed = True
        if form.data['email'] != session['email']:
            account.email = form.data['email']
            session['email'] = account.email
            changed = True
        if form.data['current_password'] and form.data['new_password'] is not '':
            current_password = form.data['current_password']
            new_password = form.data['new_password']

            if current_password != new_password:
                if bcrypt.check_password_hash(account.password, current_password):
                    account.password = bcrypt.generate_password_hash(new_password)
                    changed = True
                else:
                    flash('Invalid current password.', 'danger')

        if changed:
            flash('Successfully saved your preferences.', 'success')
            database.session.commit()
    return render_template('views/panel.html', tab='account', admins=admins, form=form)


@app.route('/panel/services', methods=['GET', 'POST'])
@authorized
def panel_services():
    return render_template('views/panel.html', tab='services', admins=admins)


@app.route('/logout')
@authorized
def logout():
    session.clear()
    flash("You're now logged out", 'success')
    return redirect(url_for('home'))


@app.route('/')
def home():
    if 'welcome_message' not in session:
        flash('Welcome to JinShop! You will not see this message again, '
              'I just want to thank you for testing this site. Have a nice day!', 'primary')
        session['welcome_message'] = True

    return render_template('views/home.html', home=True)


@app.route('/shop', methods=['GET', 'POST'])
def shop():
    if 'logged_in' in session:
        form = get_shop_form(request.form)
        form.name.data = session['minecraft_name']
    else:
        form = get_shop_form(request.form)
    default = render_template('views/shop.html',
                              sms_text='', image='', title='', sms='', prices=[],
                              modalData=None,
                              form=form,
                              shop_offers=shop_offers)
    # Someone opened the modal!
    if request.method == 'POST' and not ('Finalize' in request.form.values()):
        name = None
        for key, value in request.form.items():
            if value == 'Buy':
                name = key
        shop_offer = None
        for offer in shop_offers:
            if offer.id == name:
                shop_offer = offer
        return render_template('views/shop.html',
                               sms_text=configuration['SMS_TEXT'],
                               image=shop_offer.image,
                               title=shop_offer.name, sms=shop_offer.sms,
                               prices=configuration['PRICES'][shop_offer.sms],
                               form=form,
                               shop_offers=shop_offers, offerId=name)
    # Modal is validated successfully
    elif request.method == 'POST' and ('Finalize' in request.form.values()) and form.validate():
        name = None
        for key, value in request.form.items():
            if value == 'Finalize':
                name = key
        shop_offer = None
        for offer in shop_offers:
            if offer.id == name:
                shop_offer = offer
        code = form.data['code']
        if form.data['voucher'] is None or form.data['voucher'] is "" \
                or form.data['voucher'].isspace():
            if code is None or code is "" \
                    or code.isspace():
                code = '-0'
            voucher = False
            finalize_data = form.data['name'] + "," + code \
                            + "," + str(shop_offer.sms) + "," + shop_offer.id
        else:
            voucher = True
            finalize_data = form.data['name'] + "," + form.data['voucher'] + ",-0," + shop_offer.id

        encoded = vig.encode(finalize_data)

        return redirect(url_for('shop_finalize', encoded=encoded, voucher=voucher))
    # Modal is invalidated
    elif request.method == 'POST' and ('Finalize' in request.form.values()):
        flash('Invalid name or response code. Try again!', 'danger')
        return default

    return default


@app.route('/shop/finalize/<encoded>/<voucher>')
def shop_finalize(encoded, voucher):
    global delete_voucher
    decoded = vig.decode(encoded)
    split = decoded.split(',')
    name = split[0]
    code = split[1]
    number = split[2]
    offer_id = split[3]

    shop_offer = ""
    for offer in shop_offers:
        if offer.id == offer_id:
            shop_offer = offer
    rewards = shop_offer.rewards

    # That means this is a 'voucher call' and code becomes a voucher
    if voucher == 'True':
        voucher_data = Voucher.query.filter_by(key=code, offer=offer_id).first()
        if voucher_data is None:
            flash('That voucher does not exist or was already used!', 'danger')
            return redirect(url_for('shop'))
        voucher_data.uses -= 1
        if voucher_data.uses == 0:
            delete_voucher = True
        else:
            delete_voucher = False

        apply_rewards(name, rewards)

        if delete_voucher:
            database.session.delete(voucher_data)
        database.session.commit()
    elif check_code(number, code):
        apply_rewards(name, rewards)
    else:
        flash('Invalid code, rewards not applied', 'danger')
    return redirect(url_for('shop'))


def apply_rewards(username, rewards):
    heads.container.append(username)
    flash('Success! Your rewards were transfered to ' + username, 'success')
    split = rewards.split(';')
    for command in split:
        rcon.command(command.replace('{PLAYER}', username))


@app.context_processor
def inject_heads():
    return dict(heads=heads.container)


# Errors
@app.errorhandler(500)
def error_internal(e):
    return render_template('views/error.html',
                           errorCode=500,
                           body='Oh no! Something went wrong!')


@app.errorhandler(404)
def error_not_found(e):
    return render_template('views/error.html',
                           errorCode=404,
                           body='Oh no! The page you are looking for is missing!')


if __name__ == '__main__':
    app.run(host=app_address, port=app_port, debug=True)
