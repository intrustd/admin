from ..app import app, redis_connection, celery
from ..api import local_api, get_latest_system_hash, start_system_update, \
    make_manifest_path, AppManifest

from urllib.request import urlopen
from celery.result import AsyncResult
from celery.utils.log import get_task_logger
from celery.schedules import crontab
from celery.exceptions import Ignore

import os
import json
import contextlib
import datetime

system_update_check_running = 'intrustd-update-check-running'
system_update_running = 'intrustd-system-update-running'
latest_system_hash_key = 'intrustd-latest-system'

def app_update_check_running_key(app_url):
    return 'intrustd-update-check-{}-running'.format(app_url)

def latest_app_version_key(app_url):
    return 'intrustd-latest-app-version-{}'.format(app_url)

@contextlib.contextmanager
def run_once(self, key, fn, delete_key_countdown=None):
    with redis_connection() as redis:
        try:
            is_running = redis.get(key).decode('ascii')
        except:
            is_running = None

        if is_running is not None and is_running != self.request.id:
            r = AsyncResult(is_running, app=fn)

            if r.state in ( 'PENDING', 'STARTED' ):
                yield False
                return

        try:
            redis.set(key, self.request.id)

            yield True

        finally:
            if delete_key_countdown is None:
                redis.delete(key)
            else:
                delete_key.apply_async(args=[key], countdown=delete_key_countdown)

@celery.task(bind=True)
def check_for_app_update(self, app_url):
    with run_once(self, app_update_check_running_key(app_url), check_for_app_update) as should_run:
        if should_run:
            with local_api() as api:
                mf = api.get_application_info(app_url)
                if mf is None:
                    return

                cur_version = mf['manifest'].version_info

                # Now download current manifest
                try:
                    with urlopen(make_manifest_path(app_url)) as mf_file:
                        mf = AppManifest(json.load(mf_file))
                except Exception as e:
                    print("Could not download manifest", e) # TODO Note error in redis?
                    return

                print("Latest version", mf.version_info, "current is", cur_version)

                with redis_connection() as redis:
                    if mf.version_info > cur_version:
                        # This needs an update
                        redis.set(latest_app_version_key(app_url), json.dumps(mf.version_info).encode('ascii'))
                    else:
                        redis.delete(latest_app_version_key)

@celery.task(bind=True)
def check_for_updates(self):
    with run_once(self, system_update_check_running, check_for_updates) as should_run:
        if should_run:
            # Check for application updates as well
            with local_api() as api:
                for app in api.get_applications():
                    check_for_app_update.apply_async(args=[app.domain])

            with redis_connection() as redis:
                # Check for system updates by invoking external update script
                latest_system_hash = get_latest_system_hash()
                redis.set(latest_system_hash_key, latest_system_hash)

            # current_system_hash = get_current_system_hash()
            # TODO if the latest and current do not match and there is an option to
            # download or auto-update, then launch that
            # do_system_update.apply_async()

@celery.task(bind=True)
def do_system_update(self, download_only=False):
    with run_once(self, system_update_running, do_system_update, delete_key_countdown=5 * 60) as should_run:
        if should_run:
            self.update_state(state='STARTED',
                              meta={ 'message': 'Starting update',
                                     'total': 0, 'complete': 0 })

            log_file_dir = os.environ.get('INTRUSTD_UPDATE_LOG_DIR', "./logs")
            update_logfile_name = os.path.join(log_file_dir, datetime.datetime.now().isoformat('T'))
            os.makedirs(log_file_dir, exist_ok=True)

            for msg, total, complete in start_system_update(update_logfile_name, download_only=download_only):
                self.update_state(state='STARTED',
                                  meta = { 'message': msg,
                                           'total': total,
                                           'complete': complete })

            return True

@celery.task(bind=True)
def delete_key(self, key):
    with redis_connection() as redis:
        redis.delete(key)

celery.add_periodic_task(
    crontab(hour="*", minute="1"), # TODO allow this to be configured
    check_for_updates,
    name='Check for system updates')
