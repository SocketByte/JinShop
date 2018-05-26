from functools import wraps

import datetime

from flask import session, flash, redirect, url_for


def authorized(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized', 'danger')
            return redirect(url_for('login'))

    return wrap


def get_epoch_time():
    return round(datetime.datetime.utcnow().timestamp() * 1000)
