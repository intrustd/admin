from flask import request, jsonify, abort

from OpenSSL import crypto

from ..api import local_api, require_superuser
from ..app import app
from ..permission import Permission, TokenSet, \
    ADMIN_APP_URL, ADMIN_NUCLEAR_PERMISSION, can_request_perms_for

# Only an site with admin permissions or an app with connected clients may access this
@app.route('/container/<ip>')
def container_info(ip):
    with local_api() as api:
        if can_request_perms_for(requestor=request.remote_addr, for_ip=ip, api=api):
            ip_info = api.get_container_info(ip)
            return jsonify(ip_info)
        else:
            abort(401)

@app.route('/appliance/identity')
def appliance_identity():
    with local_api() as api:
        pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, api.private_key)

        data = { 'identity': pubkey_pem.decode('ascii'),
                 'name': api.appliance_name }

        return jsonify(data)
