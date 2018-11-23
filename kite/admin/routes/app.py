from flask import request, jsonify, abort

from ..api import local_api
from ..app import app

@app.route('/me/applications')
def my_applications():
    '''Returns a JSON list of all applications accessible to this user
    (currently, all installed apps).
    '''
    with local_api() as api:
        return jsonify([application.to_dict() for application in api.get_applications()])
