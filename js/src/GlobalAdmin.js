import { install } from 'intrustd';
import { PortalServer } from 'stork-js/src/Portal.js';
import { render } from 'react-dom';
import { createElement } from 'react';

var mainContainer, inAdminMode = false

function updateApp() {
    render(createElement(AdminApp, { inAdminMode }), mainContainer);
}

function onLogin() {
    inAdminMode = true
    updateApp()
}

install({ permissions: [ 'intrustd+perm://admin.intrustd.com/nuclear' ],
          autoLogin: true,
          loginHook: onLogin })

var { AdminApp } = require('./Admin.js') // Use require to sequence this after install


if ( location.hash.startsWith('#intrustd-auth') ) {
    window.intrustdPortalServer = new PortalServer()
} else {
    mainContainer = document.createElement('div');
    document.body.appendChild(mainContainer);
    updateApp()
}
