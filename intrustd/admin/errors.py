from flask import jsonify, request, redirect

from .app import app

class ExpectedJson(Exception):
    pass

@app.errorhandler(ExpectedJson)
def expected_json(error):
    response = jsonify({'type': 'expected-json'})
    response.status_code = 415
    return response

class MissingKey(Exception):
    def __init__(self, path=None, key=None):
        if path is None or key is None:
            raise TypeErro<r('Both path and key arguments should be set')

        self.path = path
        self.key = key

    def to_dict(self):
        return { 'type': 'missing',
                 'key': self.key,
                 'path': self.path }

@app.errorhandler(MissingKey)
def missing_key(error):
    response = jsonify(error.to_dict())
    response.status_code = 400
    return response

class WrongType(Exception):
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

@app.errorhandler(WrongType)
def wrong_type(error):
    response = jsonify(error.to_dict())
    response.status_code = 400
    return response

class PermissionDeniedError(Exception):
    def __init__(self, perms):
        self.perms = perms

    def to_dict(self):
        return { 'denied': [str(p) for p in self.perms] }

@app.errorhandler(PermissionDeniedError)
def perm_denied(error):
    response = jsonify(error.to_dict())
    response.status_code = 401
    return response

class PermissionsError(Exception):
    def __init__(self, reason):
        self.reason = reason

    @staticmethod
    def site_required():
        return PermissionsError("A site is required for this permissions set")

    @staticmethod
    def persona_required():
        return PermissionsError("A persona is required for this permissions set")

@app.errorhandler(PermissionsError)
def perm_error(error):
    response = jsonify({ "message": error.reason })
    response.status_code = 403
    return response

class AppFetchError(Exception):
    def __init__(self, msg):
        self.msg = msg

class NoSuchAppError(Exception):
    def __init__(self, app):
        self.app = app

class NoSuchAppsError(Exception):
    def __init__(self, apps):
        self.apps = list(apps)

@app.errorhandler(NoSuchAppsError)
def no_such_app_error(error):
    response = jsonify({ 'missing-apps': error.apps })
    response.status_code = 400
    return response

class NoSuchPermissionError(Exception):
    def __init__(self, permission):
        self.permission = permission

@app.errorhandler(NoSuchPermissionError)
def no_such_permission_error(error):
    response = jsonify({ 'missing-permission': error.permission })
    response.status_code = 400
    return response

class NotLoggedInError(Exception):
    pass

@app.errorhandler(NotLoggedInError)
def not_logged_in_error(error):
    return 'Not Logged In', 403

class AppInstallationError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'App install error: {}'.format(self.msg)

class LimitReached(Exception):
    def __init__(self, limit_name, max_size, actual=None):
        self.limit_name = limit_name
        self.max_size = max_size
        self.actual = actual

    def to_dict(self):
        r = { 'type': 'limit-reached',
              'limit': self.limit_name,
              'max': self.max_size }
        if self.actual is not None:
            r['actual'] = r
        return r

@app.errorhandler(LimitReached)
def limit_reached(error):
    response = jsonify(error.to_dict())
    response.status_code = 413
    return response
