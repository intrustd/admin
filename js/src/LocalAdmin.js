import { render } from 'react-dom';
import { createElement } from 'react';
import { install } from 'intrustd';

install({ rewrite: { 'admin.intrustd.com': '/admin[path]' } })

var { AdminApp } = require('./Admin.js')

var container = document.createElement('div');
document.body.appendChild(container);
render(createElement(AdminApp, {inAdminMode: true,
                                onUnauthorized: () => { location.href = '/login'; } }), container);
