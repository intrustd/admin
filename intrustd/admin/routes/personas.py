from flask import request, jsonify, abort, redirect, url_for

from ..api import local_api, require_superuser, require_logged_in
from ..app import app
from ..errors import WrongType, MissingKey
from ..util import no_cache

@app.route('/personas', methods=[ 'GET', 'POST' ])
@require_superuser(allow_local_network=True, always_allow_local_network=True,
                   require_password=True)
@no_cache
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
            raise MissingKey(path=".", key="display_name")

        if 'password' not in request.json:
            raise MissingKey(path=".", key="password")

        if not isinstance(request.json['display_name'], str):
            raise WrongType(path=".display_name", expected=WrongType.String)

        if not isinstance(request.json['password'], str):
            raise WrongType(path=".password", expected=WrongType.String)

        persona_id = api.create_user(displayname = request.json['display_name'],
                                     password = request.json['password'])

        return redirect(url_for('persona', persona_id=persona_id,
                                _scheme='intrustd+app', _external=True),
                        code=303)

@app.route('/personas/<persona_id>', methods=[ 'GET', 'PUT' ])
@require_logged_in(allow_local_network=True,
                   always_allow_local_network=True,
                   allow_apps='any')
def persona(persona_id, user=None, api=None, container=None):

    try:
        pi = api.get_persona_info(persona_id)
    except TypeError:
        abort(404)

    if pi is None:
        abort(404)

    # Container is non = local network
    if container is None or \
       (persona_id != container['persona_id'] and \
        not user.get('superuser', False)):
        abort(401)

    if request.method == 'GET':
        return jsonify({ 'persona': pi, 'persona_id': persona_id })

    elif request.method == 'PUT':
        kwargs = {}

        if request.json is None:
            abort(400)

        if 'display_name' in request.json and \
           request.json['display_name'] != pi['display_name']:
            kwargs['display_name'] = request.json['display_name']

        if 'password' in request.json:
            kwargs['password'] = request.json['password']

        def save_all():
            if len(kwargs) == 0:
                return jsonify(pi)
            else:
                abort(501) # TODO

        print("Got kwargs", kwargs)

        if 'password' in kwargs:
            save_all_auth = require_logged_in(require_password=True,
                                              allow_local_network=True,
                                              always_allow_local_network=True)(save_all)

            return save_all_auth()

        else:
            return save_all()

