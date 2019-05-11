import 'bootstrap';
import 'bootstrap/scss/bootstrap.scss';

import 'font-awesome/scss/font-awesome.scss';
import 'intrustd/src/logo-small.png';

import './Admin.scss';
import './Sidebar.scss';

import React from 'react';
import ReactDom from 'react-dom';
import TransitionGroup from 'react-transition-group/TransitionGroup';
import CSSTransition from 'react-transition-group/CSSTransition';
import { HashRouter as Router,
         Route, Switch,
         Link } from 'react-router-dom';
import { resetLogins } from 'intrustd/src/Logins.js';
import { LoadingIndicator, Image } from 'intrustd/src/react.js';

import { ADMIN_URL, fa } from './Common';
import Nav from './Navbar';

import { UserDialog, Users, UsersPage } from './Users';
import { AppsPage, Apps, AppIcon } from './Apps';
import { UpdatesPage } from './Updates';
import { ManagePage } from './Manage';

import '../static/icons/admin.svg';

const E = React.createElement;

class DiskTile extends React.Component {
    render() {
        return E('figure', { className: 'disk-tile' },
                 E('img', { className: 'disk-tile-image', src: 'https://openclipart.org/download/34537/drive-harddisk.svg' }),
                 E('caption', null, this.props.info.name))
    }
}

class Disks extends React.Component {
    constructor () {
        super()

        this.state = { disks: null }
    }

    componentDidMount() {
        fetch(`${ADMIN_URL}/storage/disks`, {cache: 'no-store'})
            .then((r) => {
                if ( r.status == 200 )
                    return r.json().then((disks) => this.setState({error: null, disks}))
                else {
                    this.setState({ error: `Invalid status: ${r.status}` })
                }
            }, (e) => { this.setState({ error: 'Error fetching disks' }) })
    }

    render() {
        console.log("Disk info is ", this.state.disks)
        var disks = E(LoadingIndicator, { key: 'loading' })

        if ( this.state.error ) {
            disks = E('div', null, this.state.error)
        } else if ( this.state.disks ) {
            disks = this.state.disks.map((disk) => E(DiskTile, { key: disk.name, info: disk }))
        }

        return E('section', { className: 'container disks-container'},
                 E('header', null,
                   E('h2', null, 'Storage Devices')),
                 disks)
    }
}

class MainPage extends React.Component {
    constructor () {
        super()
    }

    render () {
        var extra = null, header

        if ( this.props.user ) {
            if ( this.props.user.persona.superuser && this.props.inAdminMode )
                extra = [ E(Users, { key: 'users' }), E(Disks, { key: 'disks' }) ]

            header = [ E('header', { className: 'admin-header' },
                         E(Image, { className: 'avatar-image',
                                    ref: this.avatarRef,
                                    src: `${ADMIN_URL}/personas/${this.props.user.persona_id}/avatar` }),
		         E('h1', {}, `Welcome ${this.props.user.persona.display_name}`),
                           E(Link, { to: `/users/${this.props.user.persona_id}/edit`}, E('i', { className: 'fa fa-fw fa-pencil' }), ' Edit Profile')) ]
        }

        return [ header, E(Apps), extra ]
    }
}

class Sidebar extends React.Component {
    render () {
        var mkLink = (to, ...content) => E(Link, { to, className: 'list-group-item list-group-item-action bg-light'}, ...content)

        return E('div', { className: `bg-light border-right sidebar ${this.props.toggled ? 'sidebar-toggled': ''}` },
                 E('div', { className: 'list-group list-group-flush' },
                   mkLink('/', fa('tachometer'), ' Dashboard'),
                   mkLink('/apps', fa('th-large'), ' Apps'),
                   mkLink('/users', fa('users'), ' Users'),
                   mkLink('/updates', fa('download'), ' Updates'),
                   mkLink('/manage', fa('wrench'), ' Manage')))
    }

}

export class AdminApp extends React.Component {
    constructor() {
        super()

        this.avatarRef = React.createRef()
        this.state = { ourInfo: null, inAdminMode: false, sidebarToggled: false }
    }

    componentDidMount () {
        fetch(`${ADMIN_URL}/me`,
              { method: 'GET', cache: 'no-store' })
            .then((r) => {
                if ( r.status == 403 && this.props.onUnauthorized ) {
                    this.props.onUnauthorized()
                } else
                    return r.json().then((r) => this.setState({ourInfo: r}))
            })
    }

    get inAdminMode() {
        return this.state.inAdminMode || this.props.inAdminMode;
    }

    openSettings() {
        this.setState({ editingUser: true })
    }

    closeSettings() {
        this.setState({ editingUser: false })
    }

    reloadAvatar() {
        this.avatarRef.current.reload()
    }

    toggleSidebar() {
        this.setState({sidebarToggled: !this.state.sidebarToggled})
    }

    toggleAdminMode() {
        this.setState({inAdminMode: !this.inAdminMode})
    }

    render() {
        var header, editingUser;

        if ( this.state.ourInfo ) {
        }

        return E(Router, {},
                 E('div', null,
                   E(Nav, { persona: this.state.ourInfo ? this.state.ourInfo.persona : null,
                            inAdminMode: this.inAdminMode,
                            onToggleAdminMode: this.toggleAdminMode.bind(this),
                            onToggleSidebar: this.toggleSidebar.bind(this),
                            onLogout: resetLogins }),
                   E('div', { className: 'd-flex' },
                     E(Sidebar, { toggled: this.state.sidebarToggled }),
                     E('div', { className: 'page-content-wrapper' },
                       E('div', { className: 'container' },
                         header,

                         // E(Route, { path: '/me/edit',
                         //            render: ({history}) =>
                         //            E(UserDialog, { user: this.state.ourInfo,
                         //                            onClose: () => history.push('/'),
                         //                            onAvatarUpdated: this.reloadAvatar.bind(this) }) }),

                         E(Route, { path: '/', exact: true,
                                    render: () => E(MainPage, {
                                        inAdminMode: this.inAdminMode,
                                        user: this.state.ourInfo
                                    })}),

                         E(Route, { path: '/apps',
                                    render: () => E(AppsPage) }),
                         E(Route, { path: '/users',
                                    render: () => E(UsersPage) }),

                         E(Route, { path: '/updates',
                                    render: () => E(UpdatesPage) }),

                         E(Route, { path: '/manage',
                                    render: () => E(ManagePage) }))))))
    }
}
