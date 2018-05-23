import hashlib

import mcrcon
from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from util import vig
from forms import RegisterForm, LoginForm, RecoveryForm, PasswordChangeForm, SmsShopForm
from microsms.microsms import check_code
from microsms.microsms_conf import configuration
from models import ModalData
from sendmail import send_recovery_email
from util.randomstring import generate_random
from util.util import authorized, get_epoch_time

import configparser

config = configparser.ConfigParser()
config['Key'] = {
    'recaptcha_public_key': 'your recaptcha public key',
    'recaptcha_private_key': 'your recaptcha private key'
}
with open('configuration.ini', 'w') as configfile:
    config.write(configfile)

# Change that to configuration.ini!
config.read('secret_conf.ini')

RECAPTCHA_PUBLIC_KEY = config['Key']['recaptcha_public_key']
RECAPTCHA_PRIVATE_KEY = config['Key']['recaptcha_private_key']
minecraft_rcon_host = 'localhost'
minecraft_rcon_port = 25575
minecraft_rcon_password = 'rcon_password'

app_address = "localhost"
app_port = 5000

app = Flask(__name__, static_url_path='/static')
app.secret_key = 'FX7CX4JOMChRZPETQkLSpBt3gfaIfc74'  # Feel free to change it
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/minecraftshop?'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = RECAPTCHA_PUBLIC_KEY
app.config['RECAPTCHA_PRIVATE_KEY'] = RECAPTCHA_PRIVATE_KEY
database = SQLAlchemy(app)

rcon = mcrcon.MCRcon(minecraft_rcon_host,
                     minecraft_rcon_password,
                     minecraft_rcon_port)
rcon.connect()

bcrypt = Bcrypt(app)


class Account(database.Model):
    __tablename__ = "accounts"

    id = database.Column('id', database.Integer, autoincrement=True, primary_key=True)
    name = database.Column('username', database.String(30), nullable=False, unique=True)
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


def update_offers():
    app.shop_offers = ShopData.query.all()


class ShopData(database.Model):
    __tablename__ = "shop_data"

    id = database.Column('id', database.String(60), nullable=False, primary_key=True, unique=True)
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
shop_offers = ShopData.query.all()

if len(shop_offers) == 0:
    data = ShopData('default', 'Default Shop Item',
                    'Default shop item to populate shop area')
    data.sms = configuration['REQUESTS'][1]
    database.session.add(data)
    database.session.commit()
    update_offers()


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        name = form.data['username']
        email = form.data['email']

        query = Account.query.filter_by(name=name, email=email).first()
        if query is not None:
            flash("There's already someone with that nickname or email!", 'danger')
            return render_template('views/register.html', form=form)

        password = bcrypt.generate_password_hash(form.data['password'])

        account = Account(name, email, password)
        database.session.add(account)
        database.session.commit()

        flash('You are now registered!', 'success')
        return redirect(url_for('home'))

    return render_template('views/register.html', form=form)


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

                flash("You're now logged in!", 'success')
                return redirect(url_for('panel', tab='home'))
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


@app.route('/panel/<tab>')
@authorized
def panel(tab):
    return render_template('views/panel.html', tab=tab)


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
    form = SmsShopForm(request.form)
    modal_data = ModalData()
    modal_data.title = 'SMS Transaction'
    modal_data.body = 'Example SMS Body'
    modal_data.buy_path = '/'
    # Someone opened the modal!
    if request.method == 'POST' and not ('Finalize' in request.form.values()):
        name = None
        for key, value in request.form.items():
            if value == 'Buy':
                name = key
        return render_template('views/shop.html',
                               modalData=modal_data,
                               form=form,
                               shop_offers=shop_offers,
                               offerId=name)
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
            finalize_data = form.data['name'] + "," + code \
                            + "," + str(shop_offer.sms) + "," + shop_offer.id
        else:
            finalize_data = form.data['name'] + "," + form.data['voucher'] + ",-0," + shop_offer.id

        encoded = vig.encode(finalize_data)

        return redirect(url_for('shop_finalize', encoded=encoded))
    # Modal is invalidated
    elif request.method == 'POST' and ('Finalize' in request.form.values()):
        return render_template('views/shop.html',
                               modalData=modal_data,
                               form=form,
                               shop_offers=shop_offers)

    return render_template('views/shop.html',
                           modalData=None,
                           form=form,
                           shop_offers=shop_offers)


@app.route('/shop/finalize/<encoded>')
def shop_finalize(encoded):
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
    if number == "-0":
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
    flash('Success! Your rewards were transfered to ' + username, 'success')
    split = rewards.split(';')
    for command in split:
        rcon.command(command.replace('{PLAYER}', username))


if __name__ == '__main__':
    app.run(host=app_address, port=app_port, debug=True)
