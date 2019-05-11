import { ADMIN_URL, fa } from './Common';
import { AppsBase } from './Apps';

import { LoadingIndicator } from 'intrustd/src/react.js';
import { Link } from 'react-router-dom';
import TransitionGroup from 'react-transition-group/TransitionGroup';
import CSSTransition from 'react-transition-group/CSSTransition';

import React from 'react';
import ReactDom from 'react-dom';

import './Updates.scss';

const E = React.createElement;

class AppUpdate extends React.Component {
    constructor() {
        super()
        this.state = {}
    }

    componentDidMount() {
        fetch(`${ADMIN_URL}/me/applications/${this.props.appName}/manifest/latest`,
              { method: 'GET', cache: 'no-store' })
            .then((r) => {
                if ( r.status == 200 )
                    return r.json().then((app) => this.setState({app}))
                else
                    return Promise.reject()
            })
            .catch((e) => this.setState({error: true}))

    }

    mkVersion([maj, min, rev]) {
        return `${maj}.${min}.${rev}`
    }

    render() {
        if ( this.state.error )
            return []
        else if ( this.state.app ) {
            return E('li', { className: 'list-group-item app-update' },
                     E('img', { className: 'app-update-icon mr-3', src: this.state.app.icon }),
                     E('div', null,
                       E('h5', null, this.state.app.name),
                       E('div', { className: 'current-version' },
                         E('strong', null, 'Installed: '),
                         this.mkVersion(this.props.versions.current)),
                       E('div', { className: 'available-version' },
                         E('strong', null, 'Latest: '),
                         this.mkVersion(this.props.versions.latest))))
        } else
            return []
    }
}

export class UpdatesPage extends React.Component {
    constructor() {
        super()
        this.timeout = null
        this.state = {}
    }

    componentDidMount() {
        this.check()
    }

    componentWillUnmount() {
        if ( this.timeout )
            clearTimeout(this.timeout)
    }

    check() {
        fetch(`${ADMIN_URL}/system/updates/available`,
              { method: 'GET', cache: 'no-store' })
            .then(this.withCheck.bind(this))
            .catch((e) => {
                this.setState({updateError: e})
            })
    }

    withCheck(r) {
        if ( r.status == 200 )
            return r.json().then(this.withUpdateJSON.bind(this))
        else
            return Promise.reject(`Unknown status: ${r.status}`)
    }

    withUpdateJSON(updates) {
        this.setState({updates})

        if ( updates.in_progress )
            this.timeout = setTimeout(() => this.check(), 750)
        if ( updates.checking )
            this.timeout = setTimeout(() => this.check(), 10000)
        else
            this.timeout = null
    }

    checkAgain() {
        this.setState({updateError: undefined,
                       updates: undefined})
        fetch(`${ADMIN_URL}/system/updates/available`,
              { method: 'DELETE' })
            .then(this.withCheck.bind(this))
            .catch((e) => {
                this.setState({updateError: e})
            })
    }

    updateNow() {
        fetch(`${ADMIN_URL}/system/current`,
              { method: 'PUT',
                body: JSON.stringify(this.state.updates.latest_system),
                headers: { 'Content-type': 'application/json' } })
            .then((r) => {
                if ( r.status == 201 ) {
                    return this.check()
                } else if ( r.status == 409 ) {
                    if ( this.timeout ) {
                        clearTimeout(this.timeout)
                        this.timeout = null
                    }
                    this.check()
                } else
                    return Promise.reject(`Unknown status code while trying to update: ${r.status}`)
            })
            .catch((e) => {
                this.setState({updateError: `${e}`})
            })
    }

    systemUpToDate() {
        return [ E('div', { key: 'status', className: 'system-status-icon system-up-to-date-icon' },
                   E('i', { className: 'fa fa-5x fa-check' })),

                 E('p', { key: 'update-desc', className: 'system-update-description mb-0 ml-3' }, 'Your system is up-to-date') ]
    }

    checkingForUpdates() {
        return [ E('div', { key: 'status', className: 'system-status-icon system-checking-icon' },
                   E('i', { className: 'fa fa-circle-o-notch fa-5x fa-spin' })),

                 E('p', { key: 'update-desc', className: 'system-update-description mb-0 ml-3' }, 'Checking for system updates...') ]
    }

    updating({total, complete, message}) {
        return [ E('div', { key: 'status', className: 'system-status-icon system-checking-icon' },
                   E('i', { className: 'fa fa-circle-o-notch fa-5x fa-spin' })),
                 E('div', { key: 'update-desc', className: 'system-update-description mb-0 ml-3' },
                   E('p', null, `Updating: ${message}`),

                   E('div', { className: 'progress' },
                     E('div', { className: 'progress-bar',
                                role: 'progressbar',
                                'aria-valuenow': complete,
                                'aria-valuemin': 0,
                                'aria-valuemax': total,
                                style: { width: `${Math.floor(complete/total * 100)}%` } }))) ]
    }

    needsUpdate() {
        return [ E('div', { key: 'status', className: 'system-status-icon system-needs-update-icon' },
                   E('i', { className: 'fa fa-5x fa-arrow-up' })),

                 E('p', { key: 'update-desc', className: 'system-update-description mb-0 ml-3' }, 'This system needs an update')
               ]
    }

    checkAgainBtn () {
        return E('button', { className: 'btn btn-outline-primary',
                             onClick: this.checkAgain.bind(this) },
                 fa('refresh'), ' Check Again')
    }

    render() {
        var apps = E(LoadingIndicator), systemUpdate = E(LoadingIndicator), btns = []

        if ( this.state.updates ) {
            if ( this.state.updates.checking )
                systemUpdate = this.checkingForUpdates()
            else if ( this.state.updates.in_progress && !this.state.updates.in_progress.failure ) {
                systemUpdate = this.updating(this.state.updates.in_progress)
            }
            else if ( this.state.updates.latest_system == this.state.updates.current_system ) {
                systemUpdate = this.systemUpToDate()
                btns = [ this.checkAgainBtn() ]
            } else {
                systemUpdate = this.needsUpdate()
                btns = [
                    this.checkAgainBtn(),

                    E('button', { className: 'btn btn-primary ml-3',
                                  onClick: this.updateNow.bind(this) },
                      fa('arrow-up'), ' Update Now'),
                ]
            }

            if ( this.state.updates.apps ) {
                apps = [
                    E('h3', null, 'Application Updates'),
                    E('ul', { className: 'list-group'},
                      Object.keys(this.state.updates.apps).map((appName) => E(AppUpdate, { key: appName, appName, versions: this.state.updates.apps[appName] })))
                ]


            } else
                apps = E('p', null, 'All applications up-to-date')
        }

        return [ E('div', { className: 'system-updates mt-5' },
                   systemUpdate),
                 btns.length == 0 ? [] : E('div', { className: 'system-updates-btns d-flex flex-row justify-content-end' }, btns),
                 E('hr'),
                 apps ]
    }
}
