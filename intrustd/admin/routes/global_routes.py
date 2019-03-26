from flask import request, jsonify, abort

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
