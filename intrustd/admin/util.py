from flask import request
from .app import app

from OpenSSL.crypto import sign

from binascii import hexlify, unhexlify

import hashlib
import re

class Signature(object):
    def __init__(self, data, private_key=None, digest='sha256'):
        if private_key is not None:
            self.signature = sign(private_key, data, digest)

        hasher = hashlib.new(digest)
        hasher.update(data.encode('utf-8'))
        self.digest = hasher.digest()

    @property
    def hex_digest(self):
        return hexlify(self.digest).decode('ascii')

    @property
    def hex_signature(self):
        return hexlify(self.signature).decode('ascii')

def no_cache(fn):
    def no_cache_wrapped(*args, **kwargs):
        r = app.make_response(fn(*args, **kwargs))
        if 'Cache-control' not in r.headers and \
           request.method == 'GET':
            r.headers['Cache-control'] = 'no-cache'
        return r

    no_cache_wrapped.__name__ = fn.__name__
    return no_cache_wrapped

hex_digest_re = re.compile('[0-9a-fA-F]+')
def verify_hex_digest(dig):
    return hex_digest_re.match(dig) is not None
