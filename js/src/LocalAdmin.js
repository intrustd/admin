import { render } from 'react-dom';
import { createElement } from 'react';
import { installKite } from 'stork-js'

window.installKite({ rewrite: { 'admin.flywithkite.com': '/admin[path]' } })

var { AdminApp } = require('./Admin.js')

var container = document.createElement('div');
document.body.appendChild(container);
render(createElement(AdminApp, {inAdminMode: true,
                                onUnauthorized: () => { location.href = '/login'; } }), container);
