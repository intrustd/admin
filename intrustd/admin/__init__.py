from flask import request, jsonify

from .api import NoPermError, local_api, require_logged_in
from .app import app

from . import routes

@app.route('/me')
@require_logged_in(allow_guest=True, allow_local_network=True)
def me(user=None, api=None, container=None):
    if container is None: # If we're receiving this over the local network
        container = {}

    container['persona'] = user

    rsp = jsonify(container)
    rsp.headers['Cache-control'] = 'no-store'

    return rsp

@app.errorhandler(NoPermError)
def handle_no_perm(err):
    return 'Run without admin privileges', 401

with local_api() as api:
    system_type = api.get_system_type()
    app.config['SYSTEM_TYPE'] = system_type
    print("Got system type", system_type)

print("Starting intrustd admin", list(app.url_map.iter_rules()))

def main(port=80):
    app.run(host='0.0.0.0', port=port)
