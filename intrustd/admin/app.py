from flask import Flask, request
from celery import Celery, Task
from redis import BlockingConnectionPool as RedisConnectionPool, Redis
from contextlib import contextmanager
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

# TODO use a random key
app.secret_key = "INTRUSTDADMINDEBUGRANDOM BLAH"

if 'INTRUSTD_ADMIN_DEBUG' in os.environ:
    app.wsgi_app = TranslateAddressMiddleware(app.wsgi_app)

app.config.update(dict(
    PREFERRED_URL_SCHEME="intrustd+app"
))

celery = Celery(app.import_name,
                backend='redis://localhost:6379',
                broker='redis://localhost:6379')

class ContextTask(Task):
    def __call__(self, *args, **kwargs):
        with app.app_context():
            return self.run(*args, **kwargs)

celery.Task = ContextTask

_redis = RedisConnectionPool(db=1)
@contextmanager
def redis_connection():
    conn = Redis(connection_pool=_redis)
    yield conn


