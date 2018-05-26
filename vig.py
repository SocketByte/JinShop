import base64

__secret_key = 'ivMxTtmIEiEL2cZG60wKIxwO742bc9bs'


def encode(clear, key=__secret_key):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode('utf-8')).decode('utf-8')


def decode(enc, key=__secret_key):
    key = __secret_key
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode('utf-8')
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
