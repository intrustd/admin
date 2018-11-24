from flask import request, jsonify

from .api import KiteNoPermError, local_api, require_logged_in
from .app import app

from . import routes

@app.route('/me')
@require_logged_in
def me(user=None, api=None, container=None):
    print("Responding to me", request.remote_addr)

    container['persona'] = user

    rsp = jsonify(container)
    rsp.headers['Cache-control'] = 'no-store'

    return rsp

@app.errorhandler(KiteNoPermError)
def handle_no_perm(err):
    return 'Run without admin privileges', 401

print("Starting kite admin", list(app.url_map.iter_rules()))

def main():
    app.run(host='0.0.0.0', port=50051)