from flask import Flask, request
from urllib.parse import parse_qsl
import os

class TranslateAddressMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        q = environ.get('QUERY_STRING')
        if q is not None:
            q = dict(parse_qsl(q))

            if 'addr' in q:
                environ['REMOTE_ADDR'] = q['addr']

        return self.app(environ, start_response)

app = Flask(__name__)

app.secret_key = "KITEADMINDEBUGRANDOM BLAH"

if 'KITE_ADMIN_DEBUG' in os.environ:
    app.wsgi_app = TranslateAddressMiddleware(app.wsgi_app)
