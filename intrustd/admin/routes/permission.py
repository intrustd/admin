from flask import request, jsonify, abort, redirect, url_for, session
from collections.abc import Iterable
from ipaddress import ip_address, IPv4Address
from datetime import datetime, timedelta

from ..api import local_api, is_local_network
from ..app import app
from ..permission import Permission, TokenRequest, TokenSet, can_request_perms_for
from ..errors import WrongType, MissingKey, PermissionDeniedError, PermissionsError

def _validate_one_site_fingerprint(site):
    if site.startswith('SHA256:'):
        try:
            int(site[7:], 16)
            return True
        except ValueError:
            return False

    return False

def _validate_site_fingerprint(site):
    if isinstance(site, Iterable):
        sites = [s for s in site if _validate_one_site_fingerprint(s)]
    else:
        sites = [site]

    if len(sites) == 0:
        raise ValueError("Expected at least one valid site")

    return sites[0]

def _validate_tokens(tokens):
    if not isinstance(tokens, dict):
        raise ValueError("Expected map for tokens")

    ttl_seconds = None
    if 'ttl' in tokens:
        try:
            ttl_seconds = int(tokens['ttl'])
        except (ValueError, TypeError):
            raise WrongType(path=".ttl", expected=WrongType.Number)

    if 'permissions' not in tokens:
        raise MissingKey(path=".", key="permissions")
    if not isinstance(tokens['permissions'], list):
        raise WrongType(path=".permissions", expected=WrongType.List)

    permission = [Permission(p) for p in tokens['permissions']]

    if 'for_site' in tokens:
        site = _validate_site_fingerprint(tokens['for_site'])
    else:
        site = None

    return TokenRequest(permission, ttl=ttl_seconds, site=site)

def _make_tokens(api):
    tokens = req_data = request.json
    tokens = _validate_tokens(tokens)

    accept_partial = 'partial' in request.args

    on_behalf_of = req_data.get('on_behalf_of', request.remote_addr)
    if not can_request_perms_for(requestor=request.remote_addr, for_ip=on_behalf_of, api=api):
        abort(401)

    info = api.get_container_info(on_behalf_of)
    if info is None:
        abort(404)

    token = tokens.tokenize(api, persona_id=info.get('persona_id'),
                            site_id=info.get('site_id'))
    if token is None:
        abort(404)

    # Now verify that we have transfer permissions for every permission
    result = token.verify_permissions(api, info, is_transfer=tokens.is_transfer)

    if accept_partial or result.all_accepted:
        return token, result
    else:
        return None, result

@app.route('/tokens', methods=['POST'])
def tokens():
    '''How this works... Post to /tokens with a set of permissions
    and a requested expiry time, in seconds.

    You will either get back a new token, or a 401 authorization
    required with several Link: headers with rel="method"  values.

    The returned token will automatically have a scoping and an
    expiry time set. The token will not expire any later than what's
    requested in expiry time, but it may expire sooner. Please check.
    '''
    with local_api() as api:
        token, result = _make_tokens(api)
        if token is None:
            raise PermissionDeniedError(result.denied)
        else:
            token_string = token.save(api)

    return jsonify({ 'token': token_string,
                     'expiration': token.expires.isoformat() if token.expires is not None else None })

@app.route('/tokens/preview', methods=['POST'])
def tokens_preview():
    with local_api() as api:
        cur_info = api.get_container_info(request.remote_addr)
        if cur_info is None:
            abort(404)

        token, result = _make_tokens(api)
        if token is None:
            raise PermissionDeniedError(result.denied)
        else:
            description = token.describe(api, cur_info.get('persona_id'))
            return jsonify(description.to_json())

@app.route('/<addr>/permissions')
def permissions(addr):
    if addr == 'me':
        addr = request.remote_addr

    try:
        if not isinstance(ip_address(addr), IPv4Address):
            abort(404)
    except ValueError:
        abort(404)

    with local_api() as api:
        info = api.get_container_info(addr)
        if info is None:
            abort(404)

        tokens = TokenSet(api, info.get('tokens',[]))
        return jsonify([p.canonical for p in tokens.all_permissions])

@app.route('/<addr>/tokens', methods=['GET', 'POST'])
def tokens_for(addr):
    if addr == 'me':
        addr = request.remote_addr

    try:
        if not isinstance(ip_address(addr), IPv4Address):
            abort(404)
    except ValueError:
        abort(404)

    with local_api() as api:
        if not can_request_perms_for(requestor=request.remote_addr, for_ip=addr, api=api):
            abort(401)

        if request.method == 'GET':
            info = api.get_container_info(addr)
            if info is None:
                abort(404)

            return jsonify(info.get('tokens', []))
        elif request.method == 'POST':
            if not isinstance(request.json, list):
                raise WrongType('.', WrongType.List)

            for i, j in enumerate(request.json):
                if not isinstance(j, str):
                    raise WrongType('[{}]'.format(i), WrongType.String)

            for t in request.json:
                res = api.update_container(addr, credential='token:{}'.format(t))

                if res.not_allowed:
                    raise PermissionsError('Could not apply token')
                elif res.internal_error:
                    abort(500)

            info = api.get_container_info(addr)
            if info is None:
                abort(500)
            return jsonify(info.get('tokens', []))

@app.route('/login', methods=['POST'])
def do_login():
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
        if request.content_length > (16 * 1024):
            return 'Payload too large', 413

        with local_api() as api:
            info = api.get_container_info(request.remote_addr)
            if info is None:
                abort(404)

            if not info.get('logged_in', False):
                pw = request.get_data().decode('ascii')

                res = api.update_container(request.remote_addr, credential='pwd:{}'.format(pw))

                if res.not_found:
                    abort(404)
                elif res.internal_error:
                    abort(500)
                elif res.not_allowed:
                    raise PermissionsError('Could not update credentials')
                elif not res.success:
                    abort(500)

            return redirect(url_for('me', _scheme='intrustd+app', _external=True), code=303)
