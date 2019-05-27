from celery.result import AsyncResult
from flask import request, jsonify, abort, redirect, url_for
from uuid import uuid4
from datetime import datetime, timedelta
import json

from ..api import local_api, require_superuser, require_logged_in, \
    require_app_instance
from ..app import app, redis_connection, celery
from ..errors import WrongType, MissingKey, LimitReached, ExpectedJson
from ..util import no_cache
from ..db import session_scope, Task, parse_json_datetime, datetime_json
from ..tasks.task import run_scheduled_task, start_task_if_necy

MAX_DATA_LENGTH = 1024
DEFAULT_RETENTION_PERIOD = timedelta(days=7)
MAX_RETENTION_PERIOD = timedelta(days=180)

def _enrich_task_data(task, redis):
    d = task.to_json()

    d['state'] = 'queued'
    if task.finished_on is None and \
       task.started_on is not None:
        start_task_if_necy(task, redis)

        res = AsyncResult(task.id, app=run_scheduled_task)
        if res.state == 'STARTED':
            d['state'] = 'started'
            d['progress'] = res.info

    elif task.finished_on is not None:
        d['state'] = 'complete'
        if task.result is None:
            d['result'] = None
        else:
            d['result'] = json.loads(task.result)

    return d

def _tasks_for_instance(db, app_instance):
    tasks = db.query(Task).filter(Task.application == app_instance['app_url'])
    if 'persona_id' in app_instance:
        tasks = tasks.filter(Task.persona == app_instance['persona_id'])
    return tasks

@app.route('/schedule', methods=['GET', 'POST'])
@require_app_instance
@no_cache
def schedule(app_instance=None, api=None):
    if request.method == 'GET':
        # Return all tasks in schedule for this application instance
        with redis_connection() as redis, session_scope() as db:
            tasks = _tasks_for_instance(db, app_instance)

            ret = []
            for task in tasks.order_by(Task.run_after.asc()):
                ret.append(_enrich_task_data(task, redis))

            return jsonify(ret)

    elif request.method == 'POST':

        if request.json is None:
            raise ExpectedJson()

        if 'command' not in request.json:
            raise MissingKey(".", "command")
        if not isinstance(request.json['command'], str):
            raise WrongType(".command", WrongType.String)

        with session_scope() as db:
            task_id = str(uuid4())
            task = Task(id=task_id,
                        application=app_instance['app_url'],
                        command=request.json['command'])
            now = datetime.now()

            if 'persona_id' in app_instance:
                task.persona = app_instance['persona_id']

            if 'run_after' in request.json:
                if not isinstance(request.json['run_after'], str):
                    raise WrongType(".run_after", WrongType.String)

                task.run_after = parse_json_datetime(request.json['run_after'])
                if task.run_after is None:
                    raise WrongType(".run_after", "iso8601")

            if 'retain_until' in request.json:
                if not isinstance(request.json['retain_until'], str):
                    raise WrongType(".retain_until", WrongType.String)

                task.retain_until = parse_json_datetime(request.json['retain_until'])
                if task.retain_until is None:
                    raise WrongType(".retain_until", "iso8601")

                if task.retain_until < now:
                    raise LimitReached('retain_until must before now',
                                       datetime_json(now),
                                       actual=datetime_json(task.retain_until))
                if (task.retain_until - now) > MAX_RETENTION_PERIOD:
                    raise LimitReached('max task retention period',
                                       datetime_json(now + MAX_RETENTION_PERIOD),
                                       actual=task.retain_until)
            else:
                task.retain_until = now + DEFAULT_RETENTION_PERIOD

            if 'data' in request.json:
                task.data = json.dumps(request.json['data'])
                if len(task.data) > MAX_DATA_LENGTH:
                    raise LimitReached('task payload size', MAX_DATA_LENGTH,
                                       actual=len(task.data))

            if 'alias' in request.json:
                if not isinstance(request.json['alias'], str):
                    raise WrongType(".alias", WrongType.String)
                task.alias = request.json['alias']

            db.add(task)
            db.commit()

            with redis_connection() as redis:
                start_task_if_necy(task, redis)
                r = jsonify(_enrich_task_data(task, redis))
                r.status_code = 201
                r.headers['Location'] = url_for('scheduled_task', task_id=task_id,
                                                _scheme='intrustd+app', _external=True)
                return r

    else:
        abort(401)

@app.route('/schedule/<task_id>', methods=['GET', 'DELETE'])
@require_app_instance
@no_cache
def scheduled_task(app_instance=None, api=None, task_id=None):
    with session_scope() as db:
        task = _tasks_for_instance(db, app_instance).\
            filter(Task.id==task_id).one_or_none()
        if task is None:
            if request.method == 'DELETE':
                return jsonify({})

            abort(404)

        if request.method == 'GET':
            with redis_connection() as redis:
                return jsonify(_enrich_task_data(task, redis))

        elif request.method == 'DELETE':
            with redis_connection() as redis:
                task_data = _enrich_task_data(task, redis)

            if task_data['state'] != 'complete':
                print("Revoking task", task.id)
                celery.control.revoke(task.id)

            db.delete(task)
            return jsonify({})

        else:
            raise(401)
