import { ADMIN_URL, fa, uniqueId } from './Common';

import { LoadingIndicator } from 'intrustd/src/react.js';
import { Link } from 'react-router-dom';
import TransitionGroup from 'react-transition-group/TransitionGroup';
import CSSTransition from 'react-transition-group/CSSTransition';

import React from 'react';
import ReactDom from 'react-dom';

const E = React.createElement;

export class ManagePage extends React.Component {
    constructor() {
        super()
        this.autoUpdatesId = uniqueId('checkbox');
        this.state = { autoUpdates: false };
    }

    autoUpdatePrefs() {
        return E('div', { className: 'auto-update-prefs', key: 'auto-update-prefs' },
                 E('div', { className: 'form-check' },
                   E('input', { className: 'form-check-input', type: 'radio', name: 'auto-update-kind' }),
                   E('label', { className: 'form-check-label' }, 'Download only')),

                 E('div', { className: 'form-check' },
                   E('input', { className: 'form-check-input', type: 'radio', name: 'auto-update-kind' }),
                   E('label', { className: 'form-check-label' }, 'Download and install automatically')))
    }

    render() {
        return [
            E('h2', null, 'Manage Appliance'),

            E('div', null,
              E('h5', null, 'Power management'),

              E('button', { className: 'btn btn-outline-primary' },
                fa('repeat'), ' Restart'),

              E('button', { className: 'btn btn-outline-danger' },
                fa('power-off'), ' Power off')),

            E('hr'),

            E('h3', null, 'Updates'),

            E('div', { className: 'custom-control custom-switch' },
              E('input', { type: 'checkbox', className: 'custom-control-input', id: this.autoUpdatesId,
                           onChange: (e) => this.setState({autoUpdates: e.target.checked}),
                           checked: this.state.autoUpdates }),
              E('label', { className: 'custom-control-label', 'for': this.autoUpdatesId }, 'Enable Automatic Updates')),

            this.state.autoUpdates ? this.autoUpdatePrefs() : null

        ]
    }
}
