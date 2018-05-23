import requests


def url_response(url):
    return str(requests.get(url).text)
