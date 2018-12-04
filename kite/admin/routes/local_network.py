from flask import request, abort, redirect, session

from ..api import local_api, is_local_network
from ..app import app

from datetime import datetime, timedelta
import urllib.parse

@app.route('/login', methods=['POST'])
def login():
    if is_local_network():
        # If this is from the local network, check the username and
        # password fields and attempt a login, only if the user is a
        # superuser.

        if 'persona_id' in request.form and \
           'password' in request.form:
            with local_api() as api:
                persona = api.get_persona_info(request.form['persona_id'])
                if persona is None or not persona.get('superuser', False):
                    return "Unauthorized", 403
                else:
                    # TODO Verify password

                    session['persona_id'] = request.form['persona_id']
                    session['expiration'] = datetime.now() + timedelta(minutes=30)

                    if 'next' in request.args:
                        return redirect(request.args['next'])
                    else:
                        return "Logged In", 200
        else:
            return "Bad Request", 400
    else:
        return "Forbidden", 401

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

class KiteInvalidSetup(Exception):
    def __init__(self, msg, display_name=None):
        self.display_name = display_name
        self.message = msg

@app.errorhandler(KiteInvalidSetup)
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
                raise KiteInvalidSetup('Passwords do not match', display_name=request.form['displayname'])

            if len(request.form['password']) == 0:
                raise KiteInvalidSetup('Password is blank', display_name=request.form['displayname'])

            if len(request.form['displayname']) == 0:
                raise KiteInvalidSetup('Display name is blank', display_name=request.form['displayname'])

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
            raise KiteInvalidSetup('Missing form fields', display_name=request.form['displayname'])

    else:
        return "Forbidden", 401
