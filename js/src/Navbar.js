import React from 'react';
import { UploadButton, Form, PersonaButton } from 'intrustd/src/react.js';

import { fa } from './Common';

const E = React.createElement;

export default class Nav extends React.Component {
    render() {
        var securityButton

        if ( this.props.persona ) {
            var securityButton =
                E('li', { className: `nav-item ${this.props.inAdminMode ? 'active' : ''}` },
                  E('button', { className: `btn btn-outline-secondary nav-link admin-mode-button ${this.inAdminMode ? 'engaged' : ''}`,
                             'uk-tooltip': (this.props.inAdminMode ? 'Connected over local network' : 'Connected remotely. Click to enable admin privileges'),
                             onClick: this.props.onToggleAdminMode },
                    E('i', { className: `fa fa-fw ${this.props.inAdminMode ? 'fa-lock' : 'fa-unlock-alt'}` }),
                    this.props.inAdminMode ? 'Disable superuser mode' : 'Enable superuser mode' ))

        }

        return E('nav', { className: 'navbar navbar-expand-lg navbar-light bg-light border-bottom' },
                 E('button', { className: 'sidebar-toggle btn btn-outline-default my-2 my-sm-0',
                               onClick: this.props.onToggleSidebar },
                   E('i', { className: 'fa fa-fw fa-bars' })),
                 E('span', { className: 'navbar-brand mb-0' },
                   E('img', { src: 'images/logo-small.png', className: 'logo' }),
                   'Admin'),
                 E('ul', { className: 'navbar-nav ml-auto mt-2 mt-lg-0' },
                   securityButton,
                   E('li', { className: 'nav-item' },
                     E('button', { className: 'nav-link btn btn-outline-danger' },
                       fa('power-off'), 'Logout'))))
    }
}
