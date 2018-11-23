from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import reduce
from tempfile import NamedTemporaryFile
import os
import operator
import json
import re

from .util import Signature
from .errors import KitePermissionsError, KiteNoSuchAppError, \
    KiteNoSuchAppsError, KiteNoSuchPermissionError

KITE_ADMIN_APP_URL='admin.flywithkite.com'
KITE_ADMIN_NUCLEAR_PERMISSION='nuclear'
KITE_LOGIN_PERMISSION='login'
KITE_SITE_PERMISSION='site'
def get_builtin_perm(perm_name):
    if perm_name == KITE_ADMIN_NUCLEAR_PERMISSION:
        return { 'needs_site': True,
                 'needs_persona': True,
                 'needs_login': True,
                 'max_ttl': 10 * 60 } # TODO make this configurable
    elif perm_name == KITE_SITE_PERMISSION:
        return { 'needs_site': True,
                 'needs_persona': False,
                 'needs_login': False,
                 'max_ttl': 24 * 60 * 60 } # TODO make this configurable
    elif perm_name == KITE_LOGIN_PERMISSION:
        return { 'needs_site': True,
                 'needs_persona': True,
                 'needs_login': False,
                 'max_ttl': 24 * 60 * 60 }
    else:
        return None

def find_perm(perms, perm_name):
    print("Find perm", perms, perm_name)
    for p in perms:
        if 'name' in p and p['name'] == perm_name:
            return p
        elif 'regex' in p and r.fullmatch(p['regex'], perm_name):
            return p
    return None

class ApplicationUrl(object):
    def __init__(self, app_domain, app_name):
        self.domain = app_domain
        self.name = app_name

def parse_app_url(url):
    try:
        res = urlparse(url)
    except ValueError:
        raise TypeError("%s is not a valid URL" % url)

    if res.scheme != 'kite+app':
        raise TypeError("Expected kite+app as application URL scheme")

    if len(res.path) == 0 or res.path[0] != '/':
        raise ValueError("Invalid path name in application URL")

    return res.hostname

class PermSecurity(object):
    '''Permissions can only be assigned to tokens that meet certain criteria.

    For example, kite+perm://admin.flywithkite.com/nuclear (the highest
    privilege) cannot be given to a guest or a non-site token.

    This class describes what kind of token is required for this permission
    '''

    __slots__ = ( 'needs_site',
                  'needs_persona',
                  'needs_login',
                  'max_ttl', )

    def __init__(self,
                 needs_site = False,
                 needs_persona = False,
                 needs_login = False,
                 max_ttl=None):
        '''Initialize this permission security object.

        :param bool needs_site Whether or not this permission needs to be specific to a site
        :param bool needs_persona Whether or not this permission needs to be specific to a persona
        :param bool needs_login Whether or not this permission can only be applied to a token that has a contemporaneous login
        '''

        self.needs_site = needs_site
        self.needs_persona = needs_persona
        self.needs_login = needs_login
        self.max_ttl = max_ttl

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return 'PermSecurity(needs_site={self.needs_site}, needs_persona={self.needs_persona}, needs_login={self.needs_login}, max_ttl={self.max_ttl})'.format(self=self)

    def __or__(self, other):
        max_ttl = self.max_ttl
        if max_ttl is None:
            max_ttl = other.max_ttl
        elif other.max_ttl is not None:
            max_ttl = min(self.max_ttl, other.max_ttl)
        return PermSecurity(needs_site=self.needs_site or other.needs_site,
                            needs_persona=self.needs_persona or other.needs_persona,
                            needs_login=self.needs_login or other.needs_login,
                            max_ttl=max_ttl)

    @staticmethod
    def from_json(d):
        return PermSecurity(needs_site=d.get('needs_site'),
                            needs_persona=d.get('needs_persona'),
                            needs_login=d.get('needs_login'),
                            max_ttl=d.get('max_ttl'))

class Permission(object):
    def __init__(self, url_or_perm, app_url=None):
        if app_url is None:
            try:
                res = urlparse(url_or_perm)
            except ValueError:
                raise TypeError("%s is not a valid URL" % url)

            if res.scheme != 'kite+perm':
                raise TypeError("Expected kite+perm as permissions URL scheme")

            self.app = res.hostname

            if len(res.path) == 0 or res.path[0] != '/':
                raise ValueError("Invalid path name in permission")

            path = os.path.normpath(res.path)
            components = path.split('/')
            if path.startswith('//'):
                components = components[1:]

            if len(components) < 2:
                raise ValueError("Need at least one component in permission path")

            self.permission = '/'.join(components[1:])
        else:
            self.app_name = parse_app_url(app_url)
            self.permission = url_or_perm

    def __str__(self):
        return 'Permission({})'.format(self.canonical)

    def __hash__(self):
        return hash(self.canonical)

    def __eq__(self, a):
        return isinstance(a, Permission) and \
            self.app_name == a.app_name and \
            self.app_domain == a.app_domain and \
            self.permission == a.permission

    @property
    def canonical(self):
        return 'kite+perm://{}/{}'.format(self.app, self.permission)

    @property
    def application(self):
        return self.app

    def __hash__(self):
        return hash(self.canonical)

    def __eq__(self, other):
        if isinstance(other, Permission):
            return self.canonical == other.canonical
        else:
            return False

    def perm_security(self, api=None):
        if hasattr(self, '_perm_security'):
            return self._perm_security
        else:
            self._perm_security = self.lookup_perm_security(api)
            return self._perm_security

    def lookup_perm_security(self, api=None):
        '''Permission information is stored at <closure-path>/kite/perms.json

        Example:
        [ { name: "name", needs_site: true/false, needs_persona: true/false },
          { regex: "regex", dynamic: "command format" } ]
        '''

        # Find the application closure directory
        app_info = api.get_application_info(self.application)
        if app_info is None:
            raise KiteNoSuchAppError(self.application)

        manifest = app_info['manifest']
        closure = manifest.nix_closure

        # Open the permissions file
        try:
            print("Going to open", os.path.join(closure, 'permissions.json'))
            with open(os.path.join(closure, "permissions.json")) as perms:
                perms_info = json.load(perms)
                print ("Got info", perms_info)
                perm = find_perm(perms_info, self.permission)
        except FileNotFoundError:
            perm = None

        if perm is None and self.application == KITE_ADMIN_APP_URL:
            perm = get_builtin_perm(self.permission)

        if perm is None:
            raise KiteNoSuchPermissionError(self.canonical)

        if 'dynamic' in perm:
            cmd = perm['dynamic'].format({ 'persona': persona,
                                           'permission': self.permission,
                                           'application': self.application })
            sts = api.run_in_app(self.application, cmd, persona=persona, wait=True, pipe=True)
            if sts == 0:
                return l
            else:
                pass
        else:
            return PermSecurity.from_json(perm)

class TokenSet(object):
    def __init__(self, api, token_names):
        self.tokens = []
        for token_name in set(token_names):
            token = api.open_token(token_name)
            if token is not None:
                self.tokens.append(Token.from_dict(token))

    def check_permission(self, perm):
        return any(token.check_permission(perm) for token in self.tokens)

    @property
    def all_permissions(self):
        if hasattr(self, '_all_permissions'):
            return self._all_permissions
        else:
            perms = set()
            for token in self.tokens:
                perms |= token.permissions
            self._all_permissions = list(perms)
            return self._all_permissions

class TokenRequest(object):
    def __init__(self, permissions, ttl=None, site=None):
        self.permissions = permissions
        self.site = site
        if ttl is None:
            self.expiry = None
        else:
            self.expiry = datetime.now() + timedelta(seconds=ttl)

    @property
    def is_transfer(self):
        return self.site is not None

    def tokenize(self, api, persona_id=None, site_id=None):
        securities = []
        missing_apps = set()

        for p in self.permissions:
            try:
                securities.append(p.perm_security(api))
            except KiteNoSuchAppError as e:
                missing_apps.add(e.app_name)

        if len(missing_apps) > 0:
            raise KiteNoSuchAppsError(missing_apps)

        if any(security is None for security in securities):
            return None

        required_security = reduce(operator.or_, securities,
                                   PermSecurity())
        print("Required security is", required_security)

        site_needed = None
        if required_security.needs_site and site_id is None and self.site is None:
            raise KitePermissionsError.site_required()
        elif required_security.needs_site:
            site_needed = site_id
            if self.site is not None:
                site_needed = self.site

        persona_needed = None
        if required_security.needs_persona and persona_id is None:
            raise KitePermissionsError.persona_required()
        elif required_security.needs_persona:
            persona_needed = persona_id

        required_expiry = None
        if required_security.max_ttl is not None:
            required_expiry = datetime.now() + timedelta(seconds=required_security.max_ttl)

        new_expiry = self.expiry
        if new_expiry is None or required_expiry < new_expiry:
            new_expiry = required_expiry

        return Token(persona_id=persona_needed, site_id=site_needed,
                     login_required=required_security.needs_login,
                     expires=new_expiry,
                     permissions=self.permissions)

class VerificationResult(object):
    __slots__ = ('accepted', 'denied')
    def __init__(self, accepted=None, denied=None):
        if accepted is None:
            accepted = []

        if denied is None:
            denied = []

        self.accepted = accepted
        self.denied = denied

    @property
    def all_accepted(self):
        return len(self.denied) == 0

class Token(object):
    def __init__(self, persona_id=None, site_id=None, login_required=False,
                 permissions=None, expires=None):
        if permissions is None:
            permissions = []

        self.persona = persona_id
        self.site = site_id
        self.login_required = bool(login_required)
        self.expires = expires

        self.permissions = set(self._make_permission(p) for p in permissions)

    @staticmethod
    def _make_permission(p):
        if isinstance(p, Permission):
            return p
        elif isinstance(p, str):
            return Permission(p)
        else:
            raise TypeError("Permission should be 'Permission' object or string")

    def check_permission(self, p):
        return self._make_permission(p) in self.permissions

    def _verify_permission(self, p, is_transfer=False):
        '''Verify that we have the rights to transfer permissions

        We have the right to transfer permissions if we have the
        nuclear permission, or we have the perm/transfer_once or
        perm/transfer permissions

        '''
        print("_verify_permission: ", p)
        assert False

    def verify_permissions(self, api, container_info, is_transfer=False):
        accepted = []
        denied = []

        tokens = TokenSet(api, container_info.get('tokens', []))

        if container_info.get('logged_in', False) or \
           tokens.check_permission(Permission(KITE_ADMIN_NUCLEAR_PERMISSION, app_url=KITE_ADMIN_APP_URL)):
            accepted = list(self.permissions)
        else:
            for p in self.permissions:
                if self._verify_permission(p, api, is_transfer=is_transfer):
                    accepted.append(p)
                else:
                    denied.append(p)

        return VerificationResult(accepted=accepted, denied=denied)

    def to_dict(self):
        app_set = set(p.application for p in self.permissions)
        ret = { 'permissions': [p.canonical for p in self.permissions],
                'applications': list(app_set),
                'login_required': self.login_required }
        if self.persona is not None:
            ret['persona'] = self.persona
        if self.site is not None:
            ret['site'] = self.site

        if self.expires is not None:
            ret['expiration'] = self.expires.isoformat()

        return ret

    @staticmethod
    def from_dict(d):
        print("from dict", d)
        kwargs = {}
        kwargs['permissions'] = [Permission(p) for p in d.get('permissions', [])]
        if 'persona' in d:
            kwargs['persona_id'] = d['persona']
        if 'site' in d:
            kwargs['site_id'] = d['site']
        if 'expiration' in d:
            kwargs['expires'] = datetime.strptime(d['expiration'], "%Y-%m-%dT%H:%M:%S.%f")
        kwargs['login_required'] = d.get('login_required', False)
        return Token(**kwargs)

    def save(self, api):
        '''Saves this permission by writing it to a temporary file while
        calculating the sha256sum.

        Then, signs the sha256sum with our signing key and base64
        encodes the result.

        This becomes the token identifier.
        '''
        fl = NamedTemporaryFile(mode='wb', dir=api.tokens_dir)

        data = json.dumps(self.to_dict(), ensure_ascii=True)
        fl.write(data.encode('ascii'))

        sfl = Signature(data, private_key=api.private_key)

        token = "{}.{}".format(sfl.hex_digest, sfl.hex_signature)

        token_filename = os.path.join(api.tokens_dir, sfl.hex_digest)

        try:
            os.link(fl.name, token_filename)
        except FileExistsError:
            pass

        return token

