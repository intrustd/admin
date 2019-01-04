from flask import request, jsonify, abort, redirect, url_for

from ..api import local_api, require_superuser
from ..app import app
from ..errors import KiteWrongType, KiteMissingKey

@app.route('/personas', methods=[ 'GET', 'POST' ])
@require_superuser(allow_local_network=True, require_password=True)
def personas(user=None, api=None, container=None):
    if request.method == 'GET':
        user_info = []

        users = api.list_personas()
        if 'offset' in request.args:
            users = users[ int(request.args['offset']): ]
        if 'limit' in request.args:
            users = users[ :int(request.args['limit']) ]

        for user in users:
            user_info.append({ 'persona_id': user, 'persona': api.get_persona_info(user) })

        return jsonify(user_info)

    elif request.method == 'POST':
        if 'display_name' not in request.json:
            raise KiteMissingKey(path=".", key="display_name")

        if 'password' not in request.json:
            raise KiteMissingKey(path=".", key="password")

        if not isinstance(request.json['display_name'], str):
            raise KiteWrongType(path=".display_name", expected=KiteWrongType.String)

        if not isinstance(request.json['password'], str):
            raise KiteWrongType(path=".password", expected=KiteWrongType.String)

        persona_id = api.create_user(displayname = request.json['display_name'],
                                     password = request.json['password'])

        return redirect(url_for('persona', persona_id=persona_id,
                                _scheme='kite+app', _external=True),
                        code=303)

@app.route('/personas/<persona_id>', methods=[ 'GET' ])
@require_superuser(allow_local_network=True, require_password=True)
def persona(persona_id, user=None, api=None, container=None):
    try:
        api.get_persona_info(persona_id)
    except TypeError:
        abort(404)

    pi = api.get_persona_info(persona_id)
    if pi is None:
        abort(404)

    return jsonify({ 'persona': pi, 'persona_id': persona_id })

