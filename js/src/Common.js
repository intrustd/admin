import React from 'react';

export const ADMIN_URL = "intrustd+app://admin.intrustd.com";

export function fa(icon) {
    return React.createElement('i', { className: `fa fa-fw fa-${icon}` })
}

var globalId = 0;
export function uniqueId(prefix) {
    var id = globalId + 1;
    globalId = id;
    return `${prefix}-${id}`;
}
