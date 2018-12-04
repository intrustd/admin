from socket import socket, AF_UNIX, SOCK_SEQPACKET, SOL_SOCKET, SCM_RIGHTS
from contextlib import contextmanager
from OpenSSL import crypto
from flask import request, session
import fcntl
import array
import struct
import os
import ipaddress
import binascii
import json
import datetime
import select

from .app import app
from .errors import KiteNotLoggedInError, KiteAppFetchError

AttrFactory = {}

KLM_IS_LAST = 0x0002

class KiteLocalAttrClass(type):
    def __new__(cls, name, parents, dct):
        return super(KiteLocalAttrClass, cls).__new__(cls, name, parents, dct)

    def __init__(cls, name, bases, nmspc):
        ret = super(KiteLocalAttrClass, cls).__init__(name, bases, nmspc)
        if hasattr(cls, 'attr_ty'):
            AttrFactory[cls.attr_ty] = cls
        return ret

class KiteLocalAttr(object, metaclass = KiteLocalAttrClass):

    def __init__(self):
        pass

    def pack(self):
        d = self._pack()
        aligned_len = 4 * ((len(d) + 3) // 4)

        return struct.pack("!HH", self.attr_ty, len(d) + 4) + d + (b' ' * (aligned_len - len(d)))

class KiteLocalAttrAddress(KiteLocalAttr):
    attr_ty = 0x10

    def __init__(self, addr):
        super(KiteLocalAttrAddress, self).__init__()
        self.address = addr

    def _pack(self):
        return ipaddress.ip_address(self.address).packed

    @staticmethod
    def _from_buffer(attrTy, data):
        addr = ipaddress.ip_address(data).exploded
        return KiteLocalAttrAddress(addr)

class KiteLocalAttrResponseCode(KiteLocalAttr):
    attr_ty = 0x0000
    def __init__(self, code):
        super(KiteLocalAttrResponseCode, self).__init__()
        self.code = code & 0xFFFF

    def _pack(self):
        return struct.pack("!H", self.code)

    @staticmethod
    def _from_buffer(attrTy, data):
        (code,) = struct.unpack("!H", data)
        return KiteLocalAttrResponseCode(code)

    @property
    def success(self):
        return self.code == 0

    @property
    def not_found(self):
        return self.code == 7

class KiteLocalAttrContainerType(KiteLocalAttr):
    attr_ty = 0x0011

    def __init__(self, ty):
        super(KiteLocalAttrContainerType, self).__init__()
        self.ty = ty & 0xFFFF

    def _pack(self):
        return struct.pack("!H", self.ty)

    @staticmethod
    def _from_buffer(attrTy, data):
        (code,) = struct.unpack("!H", data)
        return KiteLocalAttrContainerType(code)

    @property
    def is_persona(self):
        return self.ty == 1

    @property
    def is_app_instance(self):
        return self.ty == 2

class KiteLocalAttrAppUrl(KiteLocalAttr):
    attr_ty = 0x0002

    def __init__(self, url):
        super(KiteLocalAttrAppUrl, self).__init__()
        self.url = url

    def _pack(self):
        return self.url.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrAppUrl(data.decode('ascii'))

class KiteLocalAttrPersonaDisplayName(KiteLocalAttr):
    attr_ty = 0x000D

    def __init__(self, name):
        super(KiteLocalAttrPersonaDisplayName, self).__init__()
        self.name = name

    def _pack(self):
        return self.name.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrPersonaDisplayName(data.decode('ascii'))

class KiteLocalAttrStdout(KiteLocalAttr):
    attr_ty = 0x0018

    def __init__(self, ix):
        super(KiteLocalAttrStdout, self).__init__()
        self.ix = ix

    def _pack(self):
        return struct.pack("!i", self.ix)

    @staticmethod
    def _from_buffer(attrTy, data):
        (ix,) = struct.unpack("!i", data)
        return KiteLocalAttrStdout(ix)

class KiteLocalAttrPersonaPassword(KiteLocalAttr):
    attr_ty = 0x000E

    def __init__(self, pw):
        super(KiteLocalAttrPersonaPassword, self).__init__()
        self.password = pw

    def _pack(self):
        return self.password.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrPersonaPassword(data.decode('ascii'))

class KiteLocalAttrPersonaFlags(KiteLocalAttr):
    attr_ty = 0x001D

    def __init__(self, is_superuser=False, set_flags=0, unset_flags=0):
        self.set_flags = set_flags
        self.unset_flags = unset_flags

        if is_superuser:
            self.set_flags |= 0x1

    @property
    def final_flags(self):
        return (self.set_flags & ~self.unset_flags)

    @property
    def is_superuser(self):
        return (self.final_flags & 0x1) != 0

    def _pack(self):
        return struct.pack("!ll", self.set_flags, self.unset_flags)

    @staticmethod
    def _from_buffer(attrTy, data):
        (set_flags, unset_flags,) = struct.unpack("!ll", data)
        return KiteLocalAttrPersonaFlags(set_flags = set_flags,
                                         unset_flags = unset_flags)

class KiteLocalAttrSiteId(KiteLocalAttr):
    attr_ty = 0x0013

    def __init__(self, hash_type, hash_data):
        self.hash_type = hash_type
        self.hash_data = hash_data

    @property
    def canonical(self):
        return '{}:{}'.format(self.hash_type, self.hash_data)

    def _pack(self):
        return self.canonical.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        data = data.decode('ascii').split(':')
        if len(data) != 2:
            raise ValueError("Expected site id in <hash-type>:<hash-octet> form")

        if (len(data[1]) % 2) != 0:
            raise ValueError("{} is an invalid hex string (type is {})".format(data[1], data[0]))

        try:
            payload = int(data[1], 16)
        except ValueError:
            raise ValueError("{} is an invalid site fingerprint (type is {})".format(data[1], data[0]))

        return KiteLocalAttrSiteId(data[0], data[1])

class KiteLocalAttrTokenId(KiteLocalAttr):
    attr_ty = 0x0016

    def __init__(self, token_id):
        super(KiteLocalAttrTokenId, self).__init__()
        if isinstance(token_id, str):
            self.token_id = binascii.unhexlify(token_id)
        elif isinstance(token_id, bytes):
            self.token_id = token_id[:32]
        else:
            raise TypeError("Expected 'str' or 'bytes' for token id")

        if len(self.token_id) != 32:
            raise TypeError("token id needs to be 32 bytes long")

    def _pack(self):
        return self.token_id[:32]

    @staticmethod
    def _from_buffer(attrTy, data):
        if len(data) == 32:
            return KiteLocalAttrTokenId(data)
        else:
            raise OverflowError("Expected token id of length 32, got %d" % len(data))

    @property
    def hex_str(self):
        return binascii.hexlify(self.token_id).decode('ascii')

class KiteLocalAttrPersonaId(KiteLocalAttr):
    attr_ty = 0x0001

    def __init__(self, persona_id):
        super(KiteLocalAttrPersonaId, self).__init__()
        if isinstance(persona_id, str):
            self.persona_id = binascii.unhexlify(persona_id)
        elif isinstance(persona_id, bytes):
            self.persona_id = persona_id[:32]
        else:
            raise TypeError("Expected 'str' or 'bytes' for persona id")

        if len(self.persona_id) != 32:
            raise TypeError("persona id needs to be 32 bytes long")

    def _pack(self):
        return self.persona_id[:32]

    @staticmethod
    def _from_buffer(attrTy, data):
        if len(data) == 32:
            return KiteLocalAttrPersonaId(data)
        else:
            raise OverflowError("Expected persona id of length 32, got %d" % len(data))

    @property
    def hex_str(self):
        return binascii.hexlify(self.persona_id).decode('ascii')

class KiteLocalAttrSigned(KiteLocalAttr):
    attr_ty = 0x0015

    def __init__(self):
        super(KiteLocalAttrSigned, self).__init__()

    def _pack(self):
        return b''

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrSigned()

class KiteLocalAttrManifestUrl(KiteLocalAttr):
    attr_ty = 0x0003

    def __init__(self, mf_url):
        super(KiteLocalAttrManifestUrl, self).__init__()
        self.manifest_url = mf_url

    def _pack(self):
        return self.manifest_url.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrManifestUrl(data.decode('ascii'))

class KiteLocalAttrSignatureUrl(KiteLocalAttr):
    attr_ty = 0x001F

    def __init__(self, mf_url):
        super(KiteLocalAttrSignatureUrl, self).__init__()
        self.signature_url = mf_url

    def _pack(self):
        return self.signature_url.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrSignatureUrl(data.decode('ascii'))

class KiteLocalAttrManifest(KiteLocalAttr):
    attr_ty = 0x0014

    def __init__(self, mf_name):
        super(KiteLocalAttrManifest, self).__init__()
        self.manifest = mf_name

    def _pack(self):
        return self.manifest.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrManifest(data.decode('ascii'))

class KiteLocalAttrSystemType(KiteLocalAttr):
    attr_ty = 0x001E

    def __init__(self, ty):
        super(KiteLocalAttrSystemType, self).__init__()
        self.system_type = ty

    def _pack(self):
        return self.system_type.encode('ascii')

    @staticmethod
    def _from_buffer(attrTy, data):
        return KiteLocalAttrSystemType(data.decode('ascii'))

class UnknownAttr(object):
    def __init__(self, ty, data):
        self.ty = ty
        self.data = data

    def __repr__(self):
        return "<UnknownAttr({})>".format(hex(self.ty))

    @staticmethod
    def _from_buffer(ty, data):
        return UnknownAttr(ty, data)

def find_attr(attrs, ty):
    for attr in attrs:
        if isinstance(attr, ty):
            return attr
    return None

class AppManifest(object):
    __slots__ = ( 'name', 'domain', 'nix_closures',
                  'run_as_admin', 'singleton', 'app_url',
                  'icon', )
    def __init__(self, json_data):
        self.name = json_data['name']
        self.domain = json_data['domain']
        self.nix_closures = json_data['nix-closure']
        self.run_as_admin = json_data.get('run-as-admin', False)
        self.singleton = json_data.get('singleton', False)
        self.app_url = json_data.get('app-url')
        self.icon = json_data.get('icon')

    def to_dict(self, web_response=True):
        ret = { 'name': self.name,
                'domain': self.domain,
                'app-url': self.app_url,
                'icon': self.icon } # TODO return meta information
        if not web_response:
            ret['nix-closure'] = self.nix_closures
            ret['run-as-admin'] = self.run_as_admin
            ret['singleton'] = self.singleton
        return ret

    @property
    def nix_closure(self):
        return self.nix_closures.get(app.config['KITE_SYSTEM_TYPE'])

class KiteNoPermError(Exception):
    status_code = 401

    def __init__(self):
        Exception.__init__(self)
        self.payload = "The admin application has been run without admin privileges"

class KiteLocalApi(object):
    def __init__(self, sockpath=None):
        if sockpath is None:
            if 'KITE_APPLIANCE_DIR' in os.environ:
                self.appliance_dir = os.environ['KITE_APPLIANCE_DIR']
                sockpath = os.path.join(os.environ['KITE_APPLIANCE_DIR'], 'applianced-control')
            else:
                raise TypeError("expected 'sockpath' argument or 'KITE_APPLIANCE_DIR' environment variable")

        print("Using ", sockpath, " for admin socket")

        self.socket = socket(AF_UNIX, SOCK_SEQPACKET, 0)
        try:
            self.socket.connect(sockpath)
        except FileNotFoundError:
            raise KiteNoPermError()

    def _write_request(self, req_type, flags, attrs):
        hdr = struct.pack("!HH", req_type, flags)

        return hdr + b''.join([attr.pack() for attr in attrs])

    def _receive_packet_with_flags(self):
        pkt = self.socket.recv(0x1000)

        try:
            (rspTy, rspFlags) = struct.unpack("!HH", pkt[:4])
        except struct.error as e:
            print(e)
            return None

        attrs_data = pkt[4:]
        attrs = []
        while len(attrs_data) > 0:
            try:
                (attr_ty, attr_len) = struct.unpack("!HH", attrs_data[:4])
            except struct.error as e:
                return None

            attrs.append(AttrFactory.get(attr_ty, UnknownAttr)._from_buffer(attr_ty, attrs_data[4:attr_len]))

            aligned_attr_len = 4 * ((attr_len + 3)//4)
            attrs_data = attrs_data[aligned_attr_len:]

        return (rspTy, rspFlags, attrs)

    def _receive_packet(self):
        (rspTy, _, attrs) = self._receive_packet_with_flags()

        return (rspTy, attrs)

    def _get_response_code(self, attrs):
        response_attr = find_attr(attrs, KiteLocalAttrResponseCode)
        if response_attr is None:
            raise ValueError("no response code available")
        return response_attr

    def _read_manifest(self, mf_name):
        mf_path = os.path.join(self.appliance_dir, 'manifests', mf_name)
        try:
            with open(mf_path, 'rt') as mf:
                return AppManifest(json.load(mf))
        except FileNotFoundError:
            return None

    def _get_system_info(self):
        req = self._write_request(0x0500, 0, [])

        self.socket.send(req)

        (pktTy, attrs) = self._receive_packet()

        response_attr = self._get_response_code(attrs)
        if response_attr.not_found:
            return None
        elif not response_attr.success:
            raise ValueError("error getting system information: {}".format(response_attr.code))
        else:
            return attrs

    def get_system_type(self):
        attrs = self._get_system_info()

        host = find_attr(attrs, KiteLocalAttrSystemType)
        if host is None:
            raise ValueError("No system type attribute in response")

        return host.system_type

    def create_user(self, displayname=None, password=None, superuser=False):
        req = self._write_request(0x0101, 0, [
            KiteLocalAttrPersonaDisplayName(displayname),
            KiteLocalAttrPersonaPassword(password)
        ] + ([ KiteLocalAttrPersonaFlags(is_superuser=True) ]
             if superuser else []))

        self.socket.send(req)

        (pktTy, attrs) = self._receive_packet()

        persona_id = find_attr(attrs, KiteLocalAttrPersonaId)
        if persona_id is None:
            raise ValueError("No persona id in response")

        return persona_id.hex_str

    def list_personas(self):
        req = self._write_request(0x0100, 0, [ ])

        self.socket.send(req)

        ret = []

        while True:
            (pktTy, flags, attrs) = self._receive_packet_with_flags()

            persona_id = find_attr(attrs, KiteLocalAttrPersonaId)
            if persona_id is None:
                raise ValueError("No persona id in response")

            ret.append(persona_id.hex_str)

            if ( flags & KLM_IS_LAST ) > 0:
                break

        return ret

    def get_persona_info(self, persona_id):
        req = self._write_request(0x0100, 0, [ KiteLocalAttrPersonaId(persona_id) ])
        self.socket.send(req)

        (pktTy, attrs) = self._receive_packet()

        if (pktTy & 0x8000) == 0:
            raise ValueError("Invalid reply received")
        else:
            persona = { "superuser": False,
                        "display_name": None }
            response_attr = self._get_response_code(attrs)

            if response_attr.not_found:
                return None
            elif not response_attr.success:
                raise ValueError("error looking up container: %d" % response_attr.code)

            for attr in attrs:
                if isinstance(attr, KiteLocalAttrPersonaDisplayName):
                    persona["display_name"] = attr.name
                elif isinstance(attr, KiteLocalAttrPersonaFlags):
                    if attr.is_superuser:
                        persona["superuser"] = True

            return persona

    def get_application_info(self, app_url):
        req = self._write_request(0x0200, 0, [ KiteLocalAttrAppUrl(app_url) ])
        self.socket.send(req)
        (pktTy, attrs) = self._receive_packet()

        if (pktTy & 0x8000) == 0:
            raise ValueError("Invalid reply received")
        else:
            response_attr = self._get_response_code(attrs)
            if response_attr.not_found:
                return None
            elif not response_attr.success:
                raise ValueError("error looking up application: %d" % response_attr.code)

            is_signed = find_attr(attrs, KiteLocalAttrSigned) is not None

            manifest_name = find_attr(attrs, KiteLocalAttrManifest)
            manifest = self._read_manifest(manifest_name.manifest)
            if manifest is None:
                return None

            return { 'is_signed': is_signed,
                     'manifest_name': manifest_name,
                     'manifest': manifest }

    def get_application_status(self, appid):
        state = self.get_application_info(appid)
        if state is not None:
            ret = state['manifest'].to_dict()
            ret['is_signed'] = state['is_signed']
            ret['state'] = 'installed'
            return ret
        else:
            return None

    def get_container_info(self, address):
        req = self._write_request(0x0400, 0, [ KiteLocalAttrAddress(address) ])
        self.socket.send(req)
        (pktTy, attrs) = self._receive_packet()

        if (pktTy & 0x8000) == 0:
            raise ValueError("Invalid reply received")
        else:
            found_success = False
            ty_attr = None

            success_attr = self._get_response_code(attrs)

            if success_attr.not_found:
                return None
            elif not success_attr.success:
                raise ValueError("Error looking up container: %d" % success_attr.code)

            ty_attr = find_attr(attrs, KiteLocalAttrContainerType)
            if ty_attr is None:
                raise ValueError("no container type in response")

            if ty_attr.is_persona:
                persona_id_attr = find_attr(attrs, KiteLocalAttrPersonaId)
                if persona_id_attr is None:
                    raise ValueError("no persona id in response")

                ret = { 'type': 'persona',
                        'persona_id': persona_id_attr.hex_str }

                site_id_attr = find_attr(attrs, KiteLocalAttrSiteId)
                if site_id_attr is not None:
                    ret['site_id'] = site_id_attr.canonical

                logged_in_attr = find_attr(attrs, KiteLocalAttrSigned)
                ret['logged_in'] = logged_in_attr is not None

                tokens = ret['tokens'] = []

                for attr in attrs:
                    if isinstance(attr, KiteLocalAttrTokenId):
                        tokens.append(attr.hex_str)

                return ret
            elif ty_attr.is_app_instance:
                persona_id_attr = find_attr(attrs, KiteLocalAttrPersonaId)

                app_url_attr = find_attr(attrs, KiteLocalAttrAppUrl)
                if app_url_attr is None:
                    raise ValueError("no app url in response")

                ret = { 'type': 'app_instance',
                        'app_url': app_url_attr.url }

                if persona_id_attr is not None:
                    ret['persona_id'] = persona_id_attr.hex_str

                return ret

            return None

    def close(self):
        self.socket.close()

    def send_fds(self, req, fds=[]):
        if len(fds) == 0:
            self.socket.send(req)
        else:
            self.socket.sendmsg([req], [(SOL_SOCKET,
                                         SCM_RIGHTS,
                                         array.array('i', fds))])

    @property
    def tokens_dir(self):
        tokens_dir = os.path.join(self.appliance_dir, 'tokens')
        try:
            os.makedirs(tokens_dir)
        except FileExistsError:
            pass
        return tokens_dir

    @property
    def private_key_path(self):
        return os.path.join(self.appliance_dir, 'key.pem')

    @property
    def private_key(self):
        if hasattr(self, '_private_key'):
            return self._private_key
        else:
            with open(self.private_key_path, 'rt') as private_key:
                self._private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                                           private_key.read())
                return self._private_key

    def get_applications(self):
        with open(os.path.join(self.appliance_dir, 'apps'), 'rt') as apps_file:
            for line in apps_file:
                d = line.split()
                if len(d) > 1:
                    app_id = d[0]
                    manifest_version = d[1]
                    yield self._read_manifest(manifest_version)
                else:
                    continue

    INFER_SIGN = 'infer'
    def register_application(self, manifest_path, progress=None, signature_path=None):
        progress_attr = []
        sign_attr = []
        progress_fds = []

        if progress is not None:
            rfd, wfd = os.pipe()
            progress_attr = [ KiteLocalAttrStdout(0) ]
            progress_fds = [ wfd ]

        if signature_path is not None and signature_path != self.INFER_SIGN:
            sign_attr = [ KiteLocalAttrSignatureUrl(signature_path) ]
        elif signature_path is None:
            sign_attr = [ KiteLocalAttrSignatureUrl("") ]

        req = self._write_request(0x0201, 0,
                                  [ KiteLocalAttrManifestUrl(manifest_path) ] +
                                  sign_attr +
                                  progress_attr)

        self.send_fds(req, fds=progress_fds)

        error = None
        buf = ''

        flag = fcntl.fcntl(rfd, fcntl.F_GETFD)
        fcntl.fcntl(rfd, fcntl.F_SETFD, flag | os.O_NONBLOCK)

        if progress is not None:
            # Read in the entirety of the output
            try:
                while True:
                    (r, _, x) = select.select( [ rfd, self.socket ], [], [ rfd, self.socket ] )
                    if len(x) > 0:
                        raise ValueError("Error in one or more sockets")

                    if self.socket in r:
                        break

                    if rfd in r:
                        next_chunk = os.read(rfd, 1000).decode('ascii')
                        if len(next_chunk) == 0:
                            break
                        buf += next_chunk
                        while '\n' in buf:
                            (line, _, buf) = buf.partition('\n')
                            if line.startswith('error'):
                                (_, _, msg) = line.partition(' ')
                                error = msg
                                break
                            else:
                                (complete, _, rest) = line.partition(' ')
                                (total, _, msg) = rest.partition(' ')
                                progress(msg, int(complete), int(total))
            finally:
                os.close(rfd)

        (pktTy, attrs) = self._receive_packet()

        if error is not None:
            raise KiteAppFetchError(error)

        response_attr = self._get_response_code(attrs)
        if not response_attr.success:
            raise ValueError("error getting app info: {}".format(response_attr.code))

    def open_token(self, name):
        try:
            with open(os.path.join(self.appliance_dir, 'tokens', name), 'rt') as token_file:
                return json.load(token_file)
        except FileNotFoundError:
            return None

@contextmanager
def local_api():
    r = KiteLocalApi()
    try:
        yield r
    finally:
        r.close()

def request_source():
    return request.headers.get('X-Kite-Admin-Source', 'kite-proxy')

def is_local_network():
    return request_source() == 'local-network'

def get_container_info(api):
    source = request_source()
    if source == 'local-network':

        # Check the request for a cookie, if none return unauthorized
        if 'persona_id' not in session or \
           'expiration' not in session:
            raise KiteNotLoggedInError()
        else:
            if session['expiration'] < datetime.datetime.now():
                del session['persona_id']
                del session['expiration']
                raise KiteNotLoggedInError()

            return { 'source': 'local-network',
                     'persona_id': session['persona_id'] }
    else:
        return api.get_container_info(request.remote_addr)

def require_logged_in(*args, **kwargs):
    if len(args) == 0:
        def _decorate(fn):
            return require_logged_in(fn, **kwargs)
        _decorate.__name__ = 'require_logged_in'
        return _decorate
    else:
        fn = args[0]
        options = kwargs

        def _wrapped(*args, **kwargs):

            with local_api() as api:
                kwargs['api'] = api

                try:
                    info = get_container_info(api)
                except KiteNotLoggedInError as e:
                    if options.get('allow_local_network', False):
                        info = None
                    else:
                        raise
                if info is None:
                    if options.get('allow_local_network', False) and \
                       request_source() == 'local-network':
                        kwargs['user'] = None
                        kwargs['container'] = None
                        return fn(*args, **kwargs)

                    return "Not found", 404
                else:
                    persona_id = info['persona_id']

                    persona_info = api.get_persona_info(persona_id)
                    if persona_info is not None or persona_id == ('0' * 64):
                        kwargs['user'] = persona_info
                        kwargs['container'] = info
                        return fn(*args, **kwargs)
                    else:
                        return "Unauthorized", 403
        _wrapped.__name__ = fn.__name__

        return _wrapped

def require_superuser(*args, **kwargs):
    if len(args) == 0:
        def _decorator(fn):
            return require_superuser(fn, **kwargs)
        _decorator.__name__ = 'require_superuser'
        return _decorator
    else:
        fn = args[0]
        options = kwargs

        @require_logged_in(**kwargs)
        def _wrapped(*args, **kwargs):
            if 'user' not in kwargs:
                return "Unauthorized", 403
            else:
                if (kwargs['user'] is None and options.get('allow_local_network', False)) or \
                    kwargs['user'].get('superuser', False):
                    return fn(*args, **kwargs)
                else:
                    return "Unauthorized", 403
        _wrapped.__name__ = fn.__name__

        return _wrapped
