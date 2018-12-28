from flask import request, jsonify, abort, url_for, redirect
from uuid import uuid4
from celery.result import AsyncResult

from ..api import local_api, require_logged_in, make_manifest_path
from ..permission import KITE_INSTALL_APP_PERMISSION, has_install_permission
from ..app import app, redis_connection, celery

from ..tasks.app import install_app

def _update_app_task_key(appid):
    return "update-{}".format(appid)

@app.route('/me/applications')
def my_applications():
    '''Returns a JSON list of all applications accessible to this user
    (currently, all installed apps).
    '''
    with local_api() as api:
        return jsonify([application.to_dict() for application in api.get_applications()])

@app.route('/me/applications/<appid>/status',
           methods=['GET'])
def get_application_status(appid):
    r = jsonify(_get_application_status(appid))
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

def _get_application_status(appid, task_id=None):
    with local_api() as api, redis_connection() as redis:
        app_info = api.get_application_status(appid)

    if task_id is None:
        # Look up task ids for installation or update
        task_id = redis.get(_update_app_task_key(appid))

    if app_info is None:
        if task_id is None:
            return 'Not Found', 404
        else:
            app_info = { 'state': 'not-installed',
                         'domain': appid }

    if task_id is not None:
        print("Looking up task", task_id)
        # Look up the status by getting the information from celery
        task = AsyncResult(task_id, app=install_app)

        installing = 'installing' if app_info is None else 'updating'
        state_map = { 'PENDING': installing,
                      'STARTED': installing,
                      'MANIFEST': installing,

                      'RETRY': 'error',
                      'FAILURE': 'error',
                      'SUCCESS': app_info['state'] }

        print("Got task state", task.state)

        try:
            app_info['state'] = state_map.get(task.state, 'failure')
            task_info = task.info
        except TypeError:
            app_info['state'] = 'error'
            task_info = {}
        app_info['status_url'] = url_for('get_application_status', appid=appid)

        if isinstance(task_info, Exception):
            app_info['progress'] = { 'total': 0, 'complete': 0, 'message': str(task_info) }
        elif task_info is not None:
            app_info['progress'] = { 'total': task_info.get('total', 0),
                                     'complete': task_info.get('complete', 0),
                                     'message': task_info.get('message', 'Installing...') }
        else:
            if app_info['state'] == 'installing':
                message = "Installing..."
            elif app_info['state'] == 'updating':
                message = "Updating..."
            elif app_info['state'] == 'error':
                message = "Error"
            else:
                message = "Waiting to start"
            app_info['progress'] = { 'total': 0, 'complete': 0, 'message': message }

    return app_info

@app.route('/me/applications/<appid>/version', methods=['GET'])
def application_version(appid=None):
    '''Returns the major, minor, and revision number of an application'''
    with local_api() as api:
        info = api.get_application_info(appid)
        if info is None:
            abort(404)

        mf = info['manifest']

        if mf.version_info is None:
            return jsonify({'major': 0, 'minor': 0, 'revision': 0})
        else:
            major, minor, revision = mf.version_info
            return jsonify({ 'major': major,
                             'minor': minor,
                             'revision': revision })

@app.route('/me/applications/<appid>/manifest/current', methods=['GET'])
def application_manifset(appid=None):
    with local_api() as api:
        info = api.get_application_info(appid)
        if info is None:
            abort(404)

        mf = info['manifest']
        return jsonify(mf.to_dict())

@app.route('/me/applications/<appid>/manifest/latest', methods=['GET'])
def application_latest_manifest(appid=None):
    '''Redirects to the latest version of the application manifest'''
    with local_api() as api:
        info = api.get_application_info(appid)
        if info is None:
            abort(404)

        mf = info['manifest']

        return redirect(make_manifest_path(appid), code=302)

@app.route('/me/applications/<appid>',
           methods=['GET', 'PUT'])
def application(appid=None):
    '''Returns information about the given application, or requests that a
    new installation be started
    '''

    if request.method == 'GET':
        with local_api() as api:
            app = api.get_application_status(appid)

            if app is None:
                return 'Not Found', 404
            else:
                return jsonify(app)

    elif request.method == 'PUT':

        # First determine whether the user has the ability to install
        # applications

        @require_logged_in
        def handle(api=None, user=None, container=None):
            # Lookup user permissions in our global database
            if has_install_permission(user):

                # Check redis to see if there is a celery task in progress for this application id
                with redis_connection() as redis:
                    cur_task = redis.get(_update_app_task_key(appid))
                    if cur_task is not None:
                        rsp = _get_application_status(appid, task_id=cur_task)
                        if rsp['state'] != 'installing':
                            cur_task = None

                    if cur_task is None:
                        task_id = str(uuid4())

                        redis.set(_update_app_task_key(appid), task_id)
                        install_app_task = install_app.apply_async(args=[appid], task_id=task_id)
                    else:
                        task_id = cur_task

                rsp = jsonify(_get_application_status(appid, task_id=task_id))
                if rsp.status_code == 200:
                    rsp.status_code = 202

                return rsp

            else:
                return 'Unauthorized', 401

        return handle()

    else:
        return 'Bad Method', 405

