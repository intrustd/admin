from OpenSSL.crypto import sign

from binascii import hexlify, unhexlify

import hashlib

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
