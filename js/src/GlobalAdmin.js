import { installKite } from 'stork-js'
import { PortalServer } from 'stork-js/src/Portal.js';
import { render } from 'react-dom';
import { createElement } from 'react';

window.installKite({ permissions: [ 'kite+perm://admin.flywithkite.com/nuclear' ] }) //{require_login: true})

var { AdminApp } = require('./Admin.js') // Use require to sequence this after installKite


if ( location.hash.startsWith('#kite-auth') ) {
    window.kitePortalServer = new PortalServer()
} else {
    var container = document.createElement('div');
    document.body.appendChild(container);
    render(createElement(AdminApp), container);
}
