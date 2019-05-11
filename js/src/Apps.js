import { ADMIN_URL, fa } from './Common';

import { LoadingIndicator } from 'intrustd/src/react.js';
import { Link } from 'react-router-dom';
import TransitionGroup from 'react-transition-group/TransitionGroup';
import CSSTransition from 'react-transition-group/CSSTransition';

import React from 'react';
import ReactDom from 'react-dom';

const E = React.createElement;

export class AppIcon extends React.Component {
    render() {
        var menuBtn

        if ( this.props.mkAppMenu ) {
            menuBtn = E('div', { className: 'app-tile-menu dropdown' },
                        E('button', { className: 'btn btn-secondary dropdown-toggle',
                                      type: 'button',
                                      'data-toggle': 'dropdown' },
                          fa('bars')),
                        E('div', { className: 'dropdown-menu' },
                          this.props.mkAppMenu(this.props)))
        }

        return E('div', {className: 'app-tile'},
                 menuBtn,
                 E('a', { href: this.props.appUrl },
                   E('img', { src: this.props.icon })),
                 E('div', {className: 'app-name'},
                   E('a', {href: this.props.appUrl},
                     this.props.name)));
    }
}

export class AppsBase extends React.Component {
    constructor() {
        super()
        this.state = { }
    }

    componentDidMount() {
        fetch(`${ADMIN_URL}/me/applications`,
              { method: 'GET', cache: 'no-store' })
            .then((r) => r.json())
            .then((apps) => { this.setState({apps}) })
            .catch((error) => this.setState({error}))
    }
}

export class Apps extends AppsBase {

    render() {
        var apps =
            E(CSSTransition, { timeout: 400, classNames: 'app-tile-message', id: 'loading' },
              E(LoadingIndicator, { key: 'loading' }))

        if ( this.state.apps ) {
            apps = this.state.apps.slice(0, 4).map(
                (app) =>
                    E(CSSTransition, { timeout: { enter: 500, exit: 100 },
                                       classNames: 'app-tile',
                                       id: app.canonical },
                      E(AppIcon, { icon: app.icon,
                                   name: app.name,
                                   appUrl: app['app-url'],
                                   key: app.canonical,
                                   mkAppMenu: this.props.mkAppMenu })))
        } else if ( this.state.error ) {
            apps = E(CSSTransition, { timeout: 400, classNames: 'app-tile-message', id: 'error' },
                     E('div', null, this.state.error))
        }

        return E('section', { className: 'card app-tiles-container' },
                 E('header', { className: 'card-header' },
                   E('div', { className: 'float-right' },
                     E(Link, { to: '/apps' },
                       'See all',
                       E('i', { className: 'fa fa-fw fa-caret-right'}))),
                   'Apps'),
                 E(TransitionGroup, {className: 'app-tiles'}, apps))
    }
}

export class AppsPage extends AppsBase {
    render() {
        if ( this.state.apps ) {
            var mkAppMenu = (app) => [
                E('a', { className: 'dropdown-item' },
                  fa('download'), 'Check for updates'),
                E('a', { className: 'dropdown-item' },
                  fa('trash'), ' Remove'),
                E('div', { className: 'dropdown-divider' }),
                E('a', { className: 'dropdown-item' },
                  fa('info'), ' Info')
            ]

            return E('div', { className: 'row' },
                     this.state.apps.map((app) =>
                                         E(AppIcon, { icon: app.icon,
                                                      name: app.name,
                                                      appUrl: app['app-url'],
                                                      key: app.canonical,
                                                      mkAppMenu })))
        } else
            return E(LoadingIndicator)
    }
}
