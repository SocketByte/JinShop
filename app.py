import configparser
import hashlib

from mcrcon import MCRcon
from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

from forms import LoginForm, RecoveryForm, PasswordChangeForm, get_account_form, get_shop_form, \
    ServiceForm, ServiceFormBlocked, get_voucher_form, get_config_form, RegisterForm
from heads import HeadManager
from microsms import check_code, configuration
from sendmail import send_recovery_email
import vig
from utils import authorized, get_epoch_time, generate_random

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
}
config['Permissions'] = {
    'admins': 'SocketByte,SomeoneElse'
}


def save():
    with open('configuration.ini', 'w') as configfile:
        config.write(configfile)


save()

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

# RCON
rcon = MCRcon()
rcon.connect(minecraft_rcon_host, minecraft_rcon_port, minecraft_rcon_password)

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

    def __init__(self, id, name, description, rewards):
        self.id = id
        self.name = name
        self.description = description
        self.rewards = rewards


class Voucher(database.Model):
    __tablename__ = "vouchers"

    id = database.Column('id', database.Integer, nullable=False, primary_key=True, autoincrement=True)
    key = database.Column('key', database.String(60), nullable=False, unique=True)
    offer = database.Column('offer_id', database.String(60), nullable=False)
    uses = database.Column('uses', database.Integer, nullable=False, default=1)


database.create_all()


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.data['username']
        email = form.data['email']

        query_name = Account.query.filter_by(name=name).first()
        query_email = Account.query.filter_by(email=name).first()
        if query_name or query_email is not None:
            flash("There's already someone with that nickname or email!", 'danger')
            return render_template('views/register.html', form=form)

        password = bcrypt.generate_password_hash(form.data['password'])

        account = Account(name, email, password)
        account.minecraft_name = name
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
    return render_template('views/panel.html', tab='services', admins=admins, services=ShopData.query.all())


@app.route('/panel/services/add', methods=['GET', 'POST'])
@authorized
def panel_services_add():
    form = ServiceForm()
    if form.validate_on_submit():
        shop_id = form.data['id']
        shop_name = form.data['name']

        query = ShopData.query.filter_by(id=shop_id, name=shop_name).first()
        if query is not None:
            flash('There is already a service with that ID or name!', 'danger')
            return render_template('views/panel.html', tab='service_add', admins=admins, form=form)

        shop_image = secure_filename(form.image.data.filename)
        shop_desc = form.data['description']
        shop_rewards = form.data['rewards']
        shop_number = form.data['sms_number']
        shop_commands = shop_rewards.replace('/', '')

        path = 'static/images/services/' + shop_image
        form.image.data.save(path)

        shop_data = ShopData(shop_id, shop_name, shop_desc, shop_commands)
        shop_data.sms = shop_number
        shop_data.image = path

        database.session.add(shop_data)
        database.session.commit()

        flash('Successfully added a new service!', 'success')
        return redirect(url_for('panel_services'))

    return render_template('views/panel.html', tab='service_add', admins=admins, form=form)


@app.route('/panel/services/delete/<id>', methods=['GET', 'POST'])
@authorized
def panel_services_delete(id):
    service = ShopData.query.filter_by(id=id).first()
    database.session.delete(service)
    database.session.commit()

    return redirect(url_for('panel_services'))


@app.route('/panel/services/modify/<service_id>', methods=['GET', 'POST'])
@authorized
def panel_services_modify(service_id):
    service = ShopData.query.filter_by(id=service_id).first()
    form = ServiceFormBlocked()

    if request.method == 'POST' and form.validate_on_submit():
        shop_id = form.data['id']
        shop_name = form.data['name']

        query = ShopData.query.filter_by(id=shop_id, name=shop_name).first()
        if query is None:
            flash('Error occured, unknown service.', 'danger')
            return render_template('views/panel.html', tab='service_add', admins=admins, form=form)

        shop_image = secure_filename(form.image.data.filename)
        shop_desc = form.data['description']
        shop_rewards = form.data['rewards']
        shop_number = form.data['sms_number']
        shop_commands = shop_rewards.replace('/', '')

        path = 'static/images/services/' + shop_image
        form.image.data.save(path)

        query.image = path
        query.description = shop_desc
        query.name = shop_name
        query.sms = shop_number
        query.rewards = shop_commands

        database.session.commit()
        flash('Successfully modified service with id: ' + shop_id, 'success')
        return redirect(url_for('panel_services'))
    elif request.method == 'POST':
        return render_template('views/panel.html', tab='service_modify', admins=admins, form=form)

    form.id.data = service.id
    form.rewards.data = service.rewards
    form.sms_number.data = str(service.sms)
    form.name.data = service.name
    form.description.data = service.description

    return render_template('views/panel.html', tab='service_modify', admins=admins, form=form)


@app.route('/panel/vouchers', methods=['GET', 'POST'])
@authorized
def panel_vouchers():
    form = get_voucher_form(request.form, ShopData.query.all())

    if request.method == 'POST' and form.validate():
        for_id = form.data['id']
        try:
            uses = int(form.data['uses'])
            amount = int(form.data['amount'])
        except Exception as e:
            flash('Invalid input (did you provide text instead of numbers?)', 'danger')
            return redirect(url_for('panel_vouchers'))

        vouchers = []
        for i in range(amount):
            random = generate_random(8)
            vouchers.append(random)
            voucher = Voucher()
            voucher.key = random
            voucher.offer = for_id
            voucher.uses = uses
            database.session.add(voucher)

        database.session.commit()

        return render_template('views/panel.html', tab='vouchers', admins=admins, form=form, vouchers=vouchers)

    return render_template('views/panel.html', tab='vouchers', admins=admins, form=form)


@app.route('/panel/config', methods=['GET', 'POST'])
@authorized
def panel_configuration():
    form = get_config_form(request.form, config)

    if request.method == 'POST' and form.validate():
        for header in config:
            for key in config[header]:
                config[header][key] = form.data[key]
        save()

        flash('Your settings have been saved!', 'success')
        return redirect(url_for('panel_configuration'))

    return render_template('views/panel.html', tab='config', admins=admins, form=form, config=config)


@app.route('/logout')
@authorized
def logout():
    session.clear()
    flash("You're now logged out", 'success')
    return redirect(url_for('home'))


@app.route('/')
def home():
    if 'welcome_message' not in session:
        flash('Welcome to JinShop! '
              'I just want to thank you for testing this site. Have a nice day!', 'primary')
        session['welcome_message'] = True

    return render_template('views/home.html', home=True)


@app.route('/shop', methods=['GET', 'POST'])
def shop():
    offers = ShopData.query.all()
    if 'logged_in' in session:
        form = get_shop_form(request.form)
        form.name.data = session['minecraft_name']
    else:
        form = get_shop_form(request.form)
    default = render_template('views/shop.html',
                              sms_text='', image='', title='', sms='', prices=[],
                              modalData=None,
                              form=form,
                              shop_offers=offers)
    # Someone opened the modal!
    if request.method == 'POST' and not ('Finalize' in request.form.values()):
        name = None
        for key, value in request.form.items():
            if value == 'Buy':
                name = key
        shop_offer = None
        for offer in offers:
            if offer.id == name:
                shop_offer = offer
        return render_template('views/shop.html',
                               sms_text=configuration['SMS_TEXT'],
                               image=shop_offer.image,
                               title=shop_offer.name, sms=shop_offer.sms,
                               prices=configuration['PRICES'][shop_offer.sms],
                               form=form,
                               shop_offers=offers, offerId=name)
    # Modal is validated successfully
    elif request.method == 'POST' and ('Finalize' in request.form.values()) and form.validate():
        name = None
        for key, value in request.form.items():
            if value == 'Finalize':
                name = key
        shop_offer = None
        for offer in offers:
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
    offers = ShopData.query.all()

    global delete_voucher
    decoded = vig.decode(encoded)
    split = decoded.split(',')
    name = split[0]
    code = split[1]
    number = split[2]
    offer_id = split[3]

    shop_offer = ""
    for offer in offers:
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

        apply_rewards(name, rewards, shop_offer.name)

        if delete_voucher:
            database.session.delete(voucher_data)
        database.session.commit()
    elif check_code(number, code):
        apply_rewards(name, rewards, shop_offer.name)
    else:
        flash('Invalid code, rewards not applied', 'danger')
    return redirect(url_for('shop'))


def apply_rewards(username, rewards, name):
    heads.container.append(username)
    heads.services[username] = name
    flash('Success! Your rewards were transfered to ' + username, 'success')
    if rcon is not None:
        split = rewards.split(';')
        for command in split:
            rcon.command(command.replace('{PLAYER}', username))


@app.context_processor
def inject_heads():
    return dict(heads=heads)


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
