from celery.utils.log import get_task_logger
from urllib.request import urlretrieve
from urllib.parse import quote as urlquote
from tempfile import mkdtemp
from base64 import b64encode
import os
import json

from ..api import AppManifest, local_api, make_manifest_path, make_signature_path
from ..app import celery
from ..errors import KiteAppFetchError, KiteAppInstallationError

logger = get_task_logger(__name__)

@celery.task(bind=True)
def install_app(self, appid):
    try:
        _install_app(self, appid)
    except Exception as e:
        import traceback
        traceback.print_exc()

        raise ValueError('App installation failed: {}'.format(str(e)))

def _install_app(self, appid):
    '''Install an application given an app identifier. This task

    1. Downloads the latest application manifest
    2. Checks to see if it differs from the one currently installed
    3. Downloads the closure for the current system
    4. Updates the manifest via the local API
    '''

    MANIFEST_MAX_PROGRESS = 90
    MANIFEST_SIGN_MAX_PROGRESS=10
    TMP_DIR = mkdtemp()

    def update_progress(complete, total, message):
        logger.info(message)
        self.update_state(state='STARTED',
                          meta = { 'message': message,
                                   'total': total, 'complete': complete })

    update_progress(0, 1000, 'Fetching manifest')

    def progress_report(base, max, msg):
        def report(bCount, bSize, total):
            if total < 0:
                update_progress(0, 0, msg)
            else:
                progress = max * (float(bCount * bSize) / total)
                update_progress(progress + base, 1000, msg)
        return report

    manifest_path = os.path.join(TMP_DIR, 'manifest.json')

    urlretrieve(make_manifest_path(appid), manifest_path,
                reporthook=progress_report(0, MANIFEST_MAX_PROGRESS, 'Fetching manifest'))

    try:
        urlretrieve(make_signature_path(appid), os.path.join(TMP_DIR, "manifest.json.sign"),
                    reporthook=progress_report(MANIFEST_MAX_PROGRESS, MANIFEST_SIGN_MAX_PROGRESS,
                                               'Fetching manifest signature'))

    except:
        print("Could not find manifest.json.sign")

    # Examine the manifest for the proper nix closure
    with open(manifest_path, "rt") as mf_file:
        mf = AppManifest(json.load(mf_file))
        mf_uri = "data:application/json;base64,{}".format(urlquote(b64encode(json.dumps(mf.to_dict(web_response=False)).encode('ascii')).decode('ascii')))

    def send_nix_progress(msg, complete, total):
        p = (complete / float(total)) * 900
        update_progress(100 + p, 1000, msg)

    with local_api() as api:
        try:
            api.register_application(mf_uri, progress=send_nix_progress)
        except KiteAppFetchError as e:
            self.update_state(state='FAILURE',
                              meta = { 'message': e.msg })
        except ValueError as e:
            self.update_state(state='FAILURE',
                              meta = { 'message': 'Internal error' })
