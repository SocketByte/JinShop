import random
import string

from flask_sqlalchemy import xrange


def generate_random(size=16):
    return ''.join([random.choice(string.ascii_letters + string.digits)
                    for n in xrange(size)])
