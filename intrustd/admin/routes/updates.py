from flask import request, jsonify, abort, url_for, redirect
from celery.result import AsyncResult

import json
import uuid

from ..api import get_current_system_hash, get_latest_system_hash, local_api
from ..app import app, redis_connection, celery
from ..util import no_cache
from ..tasks.update import check_for_updates, do_system_update, \
    system_update_check_running, system_update_running, latest_system_hash_key, \
    check_for_updates, latest_app_version_key

@app.route('/system/current', methods=['GET', 'PUT'])
@no_cache
def latest_system():
    if request.method == 'GET':
        return jsonify(get_current_system_hash())

    elif request.method == 'PUT':
        new_system_hash = request.json

        if get_latest_system_hash() == new_system_hash:
            with redis_connection() as redis:
                update_task_id = str(uuid.uuid4())
                redis.set(system_update_running, update_task_id)
                do_system_update.apply_async(task_id=update_task_id)

            return jsonify(get_current_system_hash()), 201
        else:
            return '{"error": "This is not the latest system"}', 409

    else:
        return 'Bad Method', 405

@app.route('/system/updates/available', methods=['GET', 'DELETE'])
@no_cache
def available_updates():
    if request.method == 'GET':
        return get_available_updates()
    elif request.method == 'DELETE':
        start_manual_check()
        return get_available_updates()
    else:
        return 'Bad method', 405

def start_manual_check():
    check_for_updates.apply_async()

def get_available_updates():
    with redis_connection() as redis:
        update_task_id = redis.get(system_update_running)
        is_checking = redis.get(system_update_check_running)
        latest_system_hash = redis.get(latest_system_hash_key)

    apps = {}
    ret = { 'checking': is_checking is not None,
            'current_system': get_current_system_hash(),
            'latest_system': None,
            'apps': apps }

    if latest_system_hash is not None:
        ret['latest_system'] = latest_system_hash.decode('ascii')
    else:
        check_for_updates.apply_async(args=[])
        ret['checking'] = True

    if update_task_id is not None:
        task = AsyncResult(update_task_id, app=do_system_update)

        if task.state == 'PENDING':
            ret['in_progress'] = { 'total': 0, 'complete': 0,
                                   'message': 'Starting...' }
        if task.info is not None and task.state == 'STARTED':
            ret['in_progress'] = { 'total': task.info.get('total', 0),
                                   'complete': task.info.get('complete', 0),
                                   'message': task.info.get('message', 'Installing...') }
        elif task.state == 'RETRY':
            ret['in_progress'] = { 'total': 0, 'complete': 0,
                                   'message': 'Updating...' }
        elif task.state == 'FAILURE' and isinstance(task.info, ValueError):
            ret['in_progress'] = { 'failed': True,
                                   'message': task.info.args[0] }

    with redis_connection() as redis:
        with local_api() as api:
            for mf in api.get_applications():

                app_url = mf.domain
                latest = redis.get(latest_app_version_key(app_url))

                if latest is not None:
                    try:
                        latest = json.loads(latest.decode('ascii'))
                    except:
                        continue

                    if not isinstance(latest, list) or len(latest) != 3:
                        continue

                    apps[app_url] = { 'current': mf.version_info,
                                      'latest': latest }

    return jsonify(ret)
