from microsms.url_api import url_response
from microsms.microsms_conf import configuration


def check_code(number, code):
    response = url_response("https://microsms.pl/api/check.php?userid={}&number={}&code={}&serviceid={}"
                            .format(configuration['USER_ID'], number, code, configuration['SERVICE_ID']))

    parsed = response.split(',')
    if parsed[0] is '1':
        return True  # valid code
    elif parsed[0] is '0':
        return False  # invalid code
    else:
        return False  # invalid request or other error
