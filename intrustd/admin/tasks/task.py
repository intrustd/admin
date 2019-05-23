from ..api import local_api
from ..app import app, celery, redis_connection
from ..db import session_scope, Task

from celery.schedules import crontab

from datetime import datetime
import os
import json

def task_key(task_id):
    return "scheduled-task-{}".format(task_id)

@celery.task(bind=True)
def run_scheduled_task(self):
    with session_scope() as db, local_api() as api:
        task = db.query(Task).get(self.request.id)
        if task is None:
            return

        task.started_on = datetime.now()
        db.commit()


        c = api.run_in_app('intrustd+app://{}'.format(task.application),
                           task.command,
                           persona=task.persona,
                           stdout=api.PIPE)

        try:
            stdout = os.fdopen(c.stdout, 'rt')
            sts = None
            for line in stdout:
                try:
                    d = json.loads(line)
                    sts = { 'data': d }
                except ValueError:
                    sts = { 'unparsed': line }

                self.update_state(state='STARTED',
                                  meta=sts)

            c.wait()

            task.finished_on = datetime.now()
            sts['status'] = c.returncode
            task.result = json.dumps(sts)
            db.commit()

            return sts
        finally:
            c.close()

@celery.task(bind=True)
def delete_finished_tasks(self):
    with session_scope() as db:
        db.query(Task).filter(Task.finished_on.isnot(None),
                              Task.retain_until < datetime.now()) \
                      .delete()

@celery.task(bind=True)
def restart_uncompleted_tasks(self):
    with redis_connection() as redis, session_scope() as db:
        tasks = db.query(Task).filter(Task.finished_on == None)
        now = datetime.now()
        for task in tasks:
            start_task_if_necy(task, redis, now=now)

def start_task_if_necy(task, redis, now=None):
    if now is None:
        now = datetime.now()

    if redis.get(task_key(task.id)) is None:
        redis.set(task_key(task.id), b'')
        if task.run_after < now:
            run_scheduled_task.apply_async(task_id=task.id)
        else:
            run_scheduled_task.apply_async(task_id=task.id,
                                           eta=task.run_after)

celery.add_periodic_task(
    crontab(hour=0, minute=0), # Daily at midnight
    delete_finished_tasks,
    name='Delete completed tasks')

