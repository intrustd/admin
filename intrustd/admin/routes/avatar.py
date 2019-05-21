from flask import request, jsonify, abort, redirect, url_for, session, send_file

from ..api import local_api, is_local_network, require_logged_in
from ..app import app

from urllib.parse import urlparse
from base64 import b64decode
from PIL import Image

import os
import io

@app.route('/personas/<persona_id>/avatar', methods=['GET', 'PUT', 'POST'])
@require_logged_in(allow_local_network=True, always_allow_local_network=True)
def avatar(user=None, api=None, container=None, persona_id=None):
    if request.method == 'GET':
        try:
            pi = api.get_persona_info(persona_id, include_photo=True)
        except TypeError:
            abort(404)

        if pi is None:
            abort(404)

        if os.path.exists(api.avatar_path(persona_id)):
            return send_file(api.avatar_path(persona_id), 'image/png')
        else:
            abort(404) # TODO provide default image

    elif request.method == 'PUT' or request.method == 'POST':
        if user.get('id', '') != persona_id and user.get('superuser', False):
            abort(401)

        if 'photo' not in request.files:
            abort(400)

        uploaded = request.files['photo']
        with Image.open(uploaded.stream) as im:
            width, height = im.size
            print("Got image size", im.size)
            if width != 64 or height != 64:
                return 'Expected 64 x 64 image', 400

            im.save(api.avatar_path(persona_id), 'PNG')

        api.update_user(persona_id, bump_photo=True)

        return '', 200

    else:
        abort(400)


