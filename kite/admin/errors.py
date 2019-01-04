from flask import jsonify, request, redirect

from .app import app

class KiteMissingKey(Exception):
    def __init__(self, path=None, key=None):
        if path is None or key is None:
            raise TypeError('Both path and key arguments should be set')

        self.path = path
        self.key = key

    def to_dict(self):
        return { 'type': 'missing',
                 'key': self.key,
                 'path': self.path }

@app.errorhandler(KiteMissingKey)
def missing_key(error):
    response = jsonify(error.to_dict())
    response.status_code = 400
    return response

class KiteWrongType(Exception):
    Number = 'number'
    String = 'string'
    List = 'array'
    Dictionary = 'object'
    Null = 'null'

    def __init__(self, path=None, expected=None):
        if path is None or expected is None:
            raise TypeError('Both path and expected arguments should be set')

        self.path = path
        self.expected = expected

    def to_dict(self):
        return { 'type': 'wrong-type',
                 'path': self.path,
                 'expected': self.expected }

@app.errorhandler(KiteWrongType)
def wrong_type(error):
    response = jsonify(error.to_dict())
    response.status_code = 400
    return response

class KitePermissionDeniedError(Exception):
    def __init__(self, perms):
        self.perms = perms

    def to_dict(self):
        return { 'denied': [str(p) for p in self.perms] }

@app.errorhandler(KitePermissionDeniedError)
def perm_denied(error):
    response = jsonify(error.to_dict())
    response.status_code = 401
    return response

class KitePermissionsError(Exception):
    def __init__(self, reason):
        self.reason = reason

    @staticmethod
    def site_required():
        return KitePermissionsError("A site is required for this permissions set")

    @staticmethod
    def persona_required():
        return KitePermissionsError("A persona is required for this permissions set")

@app.errorhandler(KitePermissionsError)
def perm_error(error):
    response = jsonify({ "message": error.reason })
    response.status_code = 403
    return response

class KiteAppFetchError(Exception):
    def __init__(self, msg):
        self.msg = msg

class KiteNoSuchAppError(Exception):
    def __init__(self, app):
        self.app = app

class KiteNoSuchAppsError(Exception):
    def __init__(self, apps):
        self.apps = list(apps)

@app.errorhandler(KiteNoSuchAppsError)
def no_such_app_error(error):
    response = jsonify({ 'missing-apps': error.apps })
    response.status_code = 400
    return response

class KiteNoSuchPermissionError(Exception):
    def __init__(self, permission):
        self.permission = permission

@app.errorhandler(KiteNoSuchPermissionError)
def no_such_permission_error(error):
    response = jsonify({ 'missing-permission': error.permission })
    response.status_code = 400
    return response

class KiteNotLoggedInError(Exception):
    pass

@app.errorhandler(KiteNotLoggedInError)
def not_logged_in_error(error):
    return 'Not Logged In', 403

class KiteAppInstallationError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'App install error: {}'.format(self.msg)
