from flask import request, session

from ..api import local_api, is_local_network
from ..app import app

import urllib.parse

@app.route("/logout", methods=['POST'])
def logout():
    if is_local_network():
        del session['persona_id']
        del session['expiration']

        if 'next' in request.args:
            return redirect(request.args['next'])
        else:
            return "Logged Out", 200
    else:
        return "Forbidden", 401

class InvalidSetup(Exception):
    def __init__(self, msg, display_name=None):
        self.display_name = display_name
        self.message = msg

@app.errorhandler(InvalidSetup)
def invalid_setup(error):
    if request.referrer and request.accept_mimetypes.accept_html:
        data = { 'error': error.message }
        if error.display_name is not None:
            data['displayname'] = error.display_name

        path = urllib.parse.urlparse(request.referrer).path

        return redirect('{}?{}'.format(path, urllib.parse.urlencode(data)))
    else:
        rsp = jsonify(error.message)
        rsp.status_code = 400
        return rsp

@app.route("/setup", methods=['POST'])
def setup():
    if is_local_network():
        if 'displayname' in request.form and \
           'password' in request.form and \
           'password_again' in request.form:

            if request.form['password'] != request.form['password_again']:
                raise InvalidSetup('Passwords do not match', display_name=request.form['displayname'])

            if len(request.form['password']) == 0:
                raise InvalidSetup('Password is blank', display_name=request.form['displayname'])

            if len(request.form['displayname']) == 0:
                raise InvalidSetup('Display name is blank', display_name=request.form['displayname'])

            with local_api() as api:
                # Create a new user with the superuser attribute
                try:
                    persona_id = api.create_user(displayname=request.form['displayname'],
                                                 password=request.form['password'],
                                                 superuser=True)
                except ValueError as e:
                    return 'Internal Server Error', 500

            if request.accept_mimetypes.accept_html and \
               'next' in request.args:
                return redirect(request.args['next'])
            else:
                return jsonify({ 'persona_id': persona_id })

        else:
            raise InvalidSetup('Missing form fields', display_name=request.form['displayname'])

    else:
        return "Forbidden", 401
