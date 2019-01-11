from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import reduce
from tempfile import NamedTemporaryFile
from binascii import hexlify
from collections import OrderedDict
import os
import operator
import json
import re
import sys

from .api import local_api
from .util import Signature
from .errors import KitePermissionsError, KiteNoSuchAppError, \
    KiteNoSuchAppsError, KiteNoSuchPermissionError

KITE_ADMIN_APP_URL='admin.flywithkite.com'
KITE_INSTALL_APP_PERMISSION='install-apps'
KITE_ADMIN_NUCLEAR_PERMISSION='nuclear'
KITE_LOGIN_PERMISSION='login'
KITE_SITE_PERMISSION='site'
KITE_GUEST_PERMISSION='guest'

KITE_TRANSFER_SUFFIX='/transfer'
KITE_TRANSFER_ONCE_SUFFIX='/transfer_once'

def _has_admin_permission(p, container_info):
    base_perm = p.base_permission
    return base_perm.permission in ( KITE_INSTALL_APP_PERMISSION,
                                     KITE_ADMIN_NUCLEAR_PERMISSION,
                                     KITE_LOGIN_PERMISSION,
                                     KITE_SITE_PERMISSION,
                                     KITE_GUEST_PERMISSION )

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
    elif perm_name == KITE_GUEST_PERMISSION:
        return { 'needs_site': False,
                 'needs_persona': True,
                 'needs_login': False,
                 'max_ttl': None }
    else:
        return None

def find_perm(perms, perm_name):
    for i, p in enumerate(perms):
        if 'name' in p and p['name'] == perm_name:
            return p, i
        elif 'regex' in p and re.fullmatch(p['regex'], perm_name):
            return p, i
    return None, None

class ApplicationUrl(object):
    def __init__(self, app_domain, app_name):
        self.domain = app_domain
        self.name = app_name


class PermSecurity(object):
    '''Permissions can only be assigned to tokens that meet certain criteria.

    For example, kite+perm://admin.flywithkite.com/nuclear (the highest
    privilege) cannot be given to a guest or a non-site token.

    This class describes what kind of token is required for this permission
    '''

    __slots__ = ( 'description',
                  'needs_site',
                  'needs_persona',
                  'needs_login',
                  'max_ttl',
                  'dynamic',
                  'index', )

    def __init__(self,
                 needs_site = False,
                 needs_persona = False,
                 needs_login = False,
                 max_ttl = None,
                 dynamic = False,
                 index = None,
                 description = None):
        '''Initialize this permission security object.

        :param bool needs_site Whether or not this permission needs to be specific to a site
        :param bool needs_persona Whether or not this permission needs to be specific to a persona
        :param bool needs_login Whether or not this permission can only be applied to a token that has a contemporaneous login
        '''

        self.needs_site = needs_site
        self.needs_persona = needs_persona
        self.needs_login = needs_login
        self.max_ttl = max_ttl
        self.dynamic = dynamic
        self.index = index
        self.description = description

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return 'PermSecurity(needs_site={self.needs_site}, needs_persona={self.needs_persona}, needs_login={self.needs_login}, max_ttl={self.max_ttl}, dynamic={self.dynamic}, index={self.index}, description={self.description})'.format(self=self)

    def __or__(self, other):
        max_ttl = self.max_ttl
        if max_ttl is None:
            max_ttl = other.max_ttl
        elif other.max_ttl is not None:
            max_ttl = min(self.max_ttl, other.max_ttl)
        return PermSecurity(needs_site=self.needs_site or other.needs_site,
                            needs_persona=self.needs_persona or other.needs_persona,
                            needs_login=self.needs_login or other.needs_login,
                            max_ttl=max_ttl,
                            dynamic=self.dynamic or other.dynamic)

    @staticmethod
    def from_json(d, index=None):
        return PermSecurity(needs_site=d.get('needs_site'),
                            needs_persona=d.get('needs_persona'),
                            needs_login=d.get('needs_login'),
                            max_ttl=d.get('max_ttl'),
                            dynamic=d.get('dynamic', False),
                            description=d.get('description', None),
                            index=index)

class Permission(object):
    def __init__(self, url_or_perm, app_url=None, relative_to=None):
        if app_url is None:
            try:
                res = urlparse(url_or_perm)
            except ValueError:
                raise TypeError("%s is not a valid URL" % url)

            if res.scheme != 'kite+perm':
                if relative_to is None:
                    raise TypeError("Expected kite+perm as permissions URL scheme")
                else:
                    self.app = relative_to
            else:
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
            self.app = app_url
            self.permission = url_or_perm

    def __repr__(self):
        return 'Permission({})'.format(self.canonical)

    def __str__(self):
        return self.canonical

    def __hash__(self):
        return hash(self.canonical)

    def __eq__(self, a):
        return isinstance(a, Permission) and \
            self.app == a.app and \
            self.permission == a.permission

    @property
    def transferred(self):
        if self.permission.endswith(KITE_TRANSFER_SUFFIX):
            transferred = Permission(self.permission[:-len(KITE_TRANSFER_SUFFIX)], app_url=self.app)
            return set([transferred, self])
        elif self.permission.endswith(KITE_TRANSFER_ONCE_SUFFIX):
            transferred = Permission(self.permission[:-len(KITE_TRANSFER_ONCE_SUFFIX)], app_url=self.app)
            return set([transferred])
        else:
            return set()

    @property
    def base_permission(self):
        if self.permission.endswith(KITE_TRANSFER_SUFFIX):
            return Permission(self.permission[:-len(KITE_TRANSFER_SUFFIX)], app_url=self.app).base_permission
        elif self.permission.endswith(KITE_TRANSFER_ONCE_SUFFIX):
            return Permission(self.permission[:-len(KITE_TRANSFER_ONCE_SUFFIX)], app_url=self.app).base_permission
        else:
            return self

    @property
    def is_base(self):
        return not self.permission.endswith(KITE_TRANSFER_SUFFIX) and \
            not self.permission.endswith(KITE_TRANSFER_ONCE_SUFFIX)

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

    def perm_security(self, api=None, persona_id=None):
        if hasattr(self, '_perm_security'):
            return self._perm_security
        else:
            self._perm_security = self.lookup_perm_security(api, persona_id)
            return self._perm_security

    def lookup_perm_security(self, api=None, persona_id=None):
        '''Permission information is stored at <closure-path>/kite/perms.json

        Example:
        [ { name: "name", needs_site: true/false, needs_persona: true/false },
          { regex: "regex", dynamic: true/false } ]
        '''

        if not self.is_base:
            return self.base_permission.lookup_perm_security(api=api, persona_id=persona_id)

        # Find the application closure directory
        app_info = api.get_application_info(self.application)
        if app_info is None:
            raise KiteNoSuchAppError(self.application)

        manifest = app_info['manifest']
        closure = manifest.nix_closure

        # Open the permissions file
        try:
            with open(os.path.join(closure, "permissions.json")) as perms:
                perms_info = json.load(perms)
                perm, i = find_perm(perms_info, self.permission)
        except FileNotFoundError:
            perm = None

        if perm is None and self.application == KITE_ADMIN_APP_URL:
            perm = get_builtin_perm(self.permission)

        if perm is None:
            raise KiteNoSuchPermissionError(self.canonical)

        if perm.get('dynamic', False):
            cmd = "/app/perms --lookup /{permission} {persona_flag} --application {application}".format(
                persona_flag = ("--persona {}".format(persona_id) if persona_id is not None else ""),
                permission=self.permission, application=self.application)

            proc = api.run_in_app(self.application, cmd, persona=persona_id, wait=True,
                                  stdout=api.PIPE, stdin=None, stderr=sys.stdout)

            stdout, stderr = proc.communicate()

            if proc.returncode == 0:
                return PermSecurity.from_json(json.loads(stdout), i)
            else:
                raise KiteNoSuchPermissionError(self.permission)
        else:
            return PermSecurity.from_json(perm, i)

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

    def __iter__(self):
        return iter(self.tokens)

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
                securities.append(p.perm_security(api, persona_id))
            except KiteNoSuchAppError as e:
                missing_apps.add(e.app)

        if len(missing_apps) > 0:
            raise KiteNoSuchAppsError(missing_apps)

        if any(security is None for security in securities):
            return None

        required_security = reduce(operator.or_, securities,
                                   PermSecurity())

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
        if new_expiry is None or (required_expiry is not None and required_expiry < new_expiry):
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

    def grouped_permissions(self):
        ret = {}
        for p in self.permissions:
            if p.app in ret:
                ret[p.app].append(p)
            else:
                ret[p.app] = [p]
        return ret

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

    def _verify_dynamic_permissions(self, api, app, persona_id, cur_set, needed):
        persona_flag = ""

        if persona_id is not None:
            persona_flag = "--persona {}".format(persona_id)

        needed_arg = " ".join(("/" + x.permission) for x in needed)

        cmd = "/app/perms --check {persona_flag} --application {app} {needed_arg}".format(**locals())

        proc = api.run_in_app(app, cmd, persona=persona_id, wait=True,
                              stdout=api.PIPE, stdin=api.PIPE, stderr=sys.stdout)

        stdout, _ = proc.communicate("\n".join(str(p) for p in cur_set))

        if proc.returncode == 0:
            result = json.loads(stdout)

            accepted = set()
            denied = set()

            for a in result.get('accepted', []):
                p = Permission(a, relative_to=app)
                if p in needed:
                    accepted.add(p)
                else:
                    print("Got permission that was not requested: {} (permission={}, app={})".format(a, p.permission, p.app))

            for a in result.get('denied', []):
                p = Permission(a, relative_to=app)
                if p in needed:
                    denied.add(p)
                else:
                    print("Got permission that was not requested: {} (permission={}, app={})".format(a, p.permission, p.app))

            needed_set = needed
            missing_set = needed_set - accepted - denied

            denied |= missing_set

            return VerificationResult(accepted=accepted, denied=denied)
        else:
            return VerificationResult(accepted=set(), denied=set(needed))

    def _verify_transfer(self, transferrable_perms, app, perms, api, persona_id=None):
        '''Verify that we have the rights to transfer permissions

        We have the right to transfer permissions if we have the
        perm/transfer_once or perm/transfer permissions. However,
        these permissions may be implied by the presence of others.

        In order to determine this, we take all the permissions we
        have that are transferrable and collect them. Then, we look up
        the information for this permission in the app's
        permission.json. If the permission is marked as dynamic, then
        we ask the application whether or not the current set of
        transferrable permissions allows us to transfer this
        one. Otherwise, we assume the permission is transferrable.

        '''
        denied = set()
        accepted = set()

        for p in perms:
            if self._make_permission(p) in transferrable_perms:
                accepted.add(p)
            else:
                denied.add(p)

        # If any denied perm is dynamic, ask if this transfer is possible
        denied_perms_security = reduce(operator.or_, (p.perm_security(api, persona_id) for p in denied), PermSecurity())
        if denied_perms_security.dynamic:
            res = self._verify_dynamic_permissions(api, app, persona_id, transferrable_perms, denied)
            accepted |= res.accepted
            denied = res.denied

        return VerificationResult(accepted=accepted,
                                  denied=denied)

    def verify_permissions(self, api, container_info, is_transfer=False):
        accepted = []
        denied = []

        persona_id = container_info.get('persona_id')

        tokens = TokenSet(api, container_info.get('tokens', []))
        # Collect all transferrable permissions from tokens
        transferrable = reduce(operator.or_, (self._make_permission(p).transferred for p in tokens.all_permissions), set())

        if container_info.get('logged_in', False) or \
           tokens.check_permission(Permission(KITE_ADMIN_NUCLEAR_PERMISSION, app_url=KITE_ADMIN_APP_URL)):
            for p in self.permissions:
                if p.app == KITE_ADMIN_APP_URL:
                    if _has_admin_permission(p, container_info):
                        accepted.append(p)
                    else:
                        denied.append(p)
                else:
                    accepted.append(p)
        else:
            for app, perms in self.grouped_permissions().items():
                res = self._verify_transfer(transferrable, app, perms, api, persona_id=persona_id)
                accepted.extend(res.accepted)
                denied.extend(res.denied)

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

    def _mint_secret(self):
        MIN_SECRET_LENGTH = 128
        return hexlify(os.urandom(MIN_SECRET_LENGTH)).decode('ascii')

    def save(self, api):
        '''Saves this permission by writing it to a temporary file while
        calculating the sha256sum.

        Then, signs the sha256sum with our signing key and base64
        encodes the result.

        This becomes the token identifier.
        '''
        with NamedTemporaryFile(mode='wb', dir=api.tokens_dir) as fl:

            json_data = self.to_dict()
            json_data['secret'] = self._mint_secret()

            data = json.dumps(json_data, ensure_ascii=True)
            fl.write(data.encode('ascii'))

            sfl = Signature(data)
            token = sfl.hex_digest

            token_filename = os.path.join(api.tokens_dir, sfl.hex_digest)

            try:
                os.link(fl.name, token_filename)
            except FileExistsError:
                pass

            return token

    def describe(self, api, persona_id):
        r = TokenDescription()

        grouped = self.grouped_permissions()
        for app, perms in grouped.items():
            app_info = api.get_application_info(app)
            section = r.get_section(app_info['manifest'])

            if app == KITE_ADMIN_APP_URL:
                entries = _describe_admin_perms(perms)
            else:

                # Ask for a dynamic description
                cmd = "/app/perms --describe {persona_flag} --application {application}".format(
                    persona_flag = '' if persona_id is None else "--persona {}".format(persona_id),
                    application = app)

                proc = api.run_in_app(app, cmd, persona=persona_id, wait=True,
                                      stdout=api.PIPE, stdin=api.PIPE, stderr=sys.stdout)

                stdout, _ = proc.communicate("\n".join(p.canonical for p in perms))

                if proc.returncode == 0:
                    entries = json.loads(stdout)

                else:
                    raise ValueError("Could not describe permissions for {}: process exited with {}".format(app, proc.returncode))

            for e in entries:
                section.add_entry(e)

        return r

class TokenDescriptionEntry(object):
    __slots__ = ( 'short',
                  'long',
                  'image', )

    def __init__(self, short_or_desc, long=None, image=None):
        if isinstance(short_or_desc, str):
            self.short = short_or_desc
            self.long = long
            self.image = image

        elif isinstance(short_or_desc, dict):
            self.short = short_or_desc.get('short')
            self.long = short_or_desc.get('long', '')
            self.image = short_or_desc.get('image')

        else:
            raise TypeError("Expected either short description or JSON-dict")

        if self.short is None:
            raise TypeError("No short description given for permission")

    def to_json(self):
        r = { 'short': self.short }

        if self.long is not None:
            r['long'] = self.long

        if self.image is not None:
            r['image'] = self.image

        return r

class TokenDescriptionSection(object):
    '''Description of permissions associated with a particular application
    '''
    def __init__(self, mf, api=None, persona_id=None):
        self.app_manifest = mf
        self.entries = []
        self._api = api
        self._persona_id = persona_id
        self._all_permissions = None
        self._permissions = set()
        self._dynamic_permissions = {}

    @property
    def all_permissions(self):
        if self._all_permissions is None:
            with open(os.path.join(self.app_manifest.nix_closure, "permissions.json")) as perms:
                self._all_permissions = json.loads(perms)
        return self._all_permissions

    def add_entry(self, short_or_desc):
        entry = TokenDescriptionEntry(short_or_desc)
        self.entries.append(entry)
        return entry

    def to_json(self):
        return { 'domain': self.app_manifest.domain,
                 'name': self.app_manifest.name,
                 'run-as-admin': self.app_manifest.run_as_admin,
                 'singleton': self.app_manifest.singleton,
                 'version': self.app_manifest.version,
                 'icon': self.app_manifest.icon,

                 'entries': [ e.to_json() for e in self.entries ] }

class TokenDescription(object):
    '''Description of a set of permissions
    '''
    def __init__(self):
        self.apps = OrderedDict()

    def get_section(self, app_manifest):
        if app_manifest.domain not in self.apps:
            self.apps[app_manifest.domain] = TokenDescriptionSection(app_manifest)

        return self.apps[app_manifest.domain]

    def to_json(self):
        return { 'sections': [section.to_json() for section in self.apps.values()] }

def has_install_permission(perms):
    return Permission(KITE_INSTALL_APP_PERMISSION, KITE_ADMIN_APP_URL) in perms or \
        Permission(KITE_ADMIN_NUCLEAR_PERMISSION, KITE_ADMIN_APP_URL) in perms

def _describe_admin_perms(ps):
    ps = set(p.permission for p in ps)
    r = []

    if KITE_ADMIN_NUCLEAR_PERMISSION in ps:
        return [ { 'short': 'Administer this user' } ]

    if KITE_INSTALL_APP_PERMISSION in ps:
        r.append({ 'short': 'Install applications for this user' })

    if KITE_LOGIN_PERMISSION in ps:
        r.append({ 'short': 'Login as this user' })

    if KITE_GUEST_PERMISSION in ps:
        r.append({ 'short': 'Invite others to view this user\'s data' })

    return r
