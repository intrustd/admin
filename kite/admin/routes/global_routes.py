from flask import request, jsonify, abort

from ..api import local_api, require_superuser
from ..app import app

@app.route('/personas')
@require_superuser(allow_local_network=True, require_password=True)
def users(user=None, api=None, container=None):
    user_info = []

    users = api.list_personas()
    if 'offset' in request.args:
        users = users[ int(request.args['offset']): ]
    if 'limit' in request.args:
        users = users[ :int(request.args['limit']) ]

    for user in users:
        user_info.append({ 'persona_id': user, 'persona': api.get_persona_info(user) })

    return jsonify(user_info)
