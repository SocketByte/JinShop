import requests


def check_code(number, code):
    # You can easily change the parsing alghoritm for different SMS service providers
    response = url_response("https://microsms.pl/api/check.php?userid={}&number={}&code={}&serviceid={}"
                            .format(configuration['USER_ID'], number, code, configuration['SERVICE_ID']))

    parsed = response.split(',')
    if parsed[0] is '1':
        return True  # valid code
    elif parsed[0] is '0':
        return False  # invalid code
    else:
        return False  # invalid request or other error


def url_response(url):
    return str(requests.get(url).text)


configuration = {
    'USER_ID': 2544,
    'SERVICE_ID': 3231,
    'SMS_TEXT': 'MSMS.SOCKETBYTE',
    'PRICES': {
        71480: (1, 1.23),
        72480: (2, 2.46),
        73480: (3, 3.69),
        74480: (4, 4.92),
        75480: (5, 6.15),
        76480: (6, 7.38),
        79480: (9, 11.07),
        91400: (14, 17.22),
        91900: (19, 23.37),
        92022: (20, 24.60),
        92521: (25, 30.75)
    },
    'REQUESTS': {
        1: 71480,
        2: 72480,
        3: 73480,
        4: 74480,
        5: 75480,
        6: 76480,
        9: 79480,
        14: 91400,
        19: 91900,
        20: 92022,
        25: 92521
    },
    'DROPDOWN': [
        ('71480', '1'),
        ('72480', '2'),
        ('73480', '3'),
        ('74480', '4'),
        ('75480', '5'),
        ('76480', '6'),
        ('79480', '9'),
        ('91400', '14'),
        ('91900', '19'),
        ('92022', '20'),
        ('92521', '25')
    ]
}
