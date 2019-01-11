from flask import request, jsonify, abort

from ..api import local_api
from ..app import app
from ..util import no_cache

import pyudev

udev = pyudev.Context()

def is_physical_partition(dev):
    if dev.parent is not None:
        if dev.parent['SUBSYSTEM'] in ('scsi',):
            return True
        else:
            return is_physical_partition(dev.parent)
    else:
        return False

@app.route('/storage/disks')
@no_cache
def disks():
    '''Returns a JSON list of all available disks
    '''
    ret = []
    for dev in udev.list_devices(subsystem='block', DEVTYPE='disk'):
        if is_physical_partition(dev):
            ret.append({ 'name': dev['DEVNAME'],
                         'path': dev.device_node,
                         'partitions': [] })

    for dev in udev.list_devices(subsystem='block', DEVTYPE='partition'):
        if is_physical_partition(dev) and dev.parent is not None:
            for disk in ret:
                if disk['path'] == dev.parent.device_node:
                    disk['partitions'].append(dev.device_node)

    return jsonify(ret)
