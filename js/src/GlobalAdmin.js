import { installKite } from 'stork-js'
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

window.installKite({ permissions: [ 'kite+perm://admin.flywithkite.com/nuclear' ],
                     autoLogin: true,
                     loginHook: onLogin })

var { AdminApp } = require('./Admin.js') // Use require to sequence this after installKite


if ( location.hash.startsWith('#kite-auth') ) {
    window.kitePortalServer = new PortalServer()
} else {
    mainContainer = document.createElement('div');
    document.body.appendChild(mainContainer);
    updateApp()
}
