import UIKit from 'uikit';
//import 'uikit/src/less/uikit.less';
import './login.scss';

import 'font-awesome/scss/font-awesome.scss';

import 'stork-js/src/Authenticator.scss';

import './kite-banner.svg';

import React from 'react';
import ReactDom from 'react-dom';

import queryString from 'query-string';

const E = React.createElement;

class Logins extends React.Component {
    constructor() {
        super()
        this.state = { selectedPersona: null, needsSetup: false };
    }

    componentDidMount() {
        fetch('/admin/personas')
            .then((r) => {
                if ( r.status == 200 ) {
                    return r.json()
                        .then((r) => {
                            if ( r instanceof Array ) {
                                r = r.filter((u) => u.persona.superuser)
                                if ( r.length > 0 ) {
                                    this.setState({ personas: r })
                                } else {
                                    this.setState({ needsSetup: true })
                                }
                            } else
                                this.setState({error: "Could not fetch personas array"})
                        })
                } else {
                    this.setState({error: `Error fetching personas (Status: ${r.status})`})
                }
            })
    }

    render() {
        if ( this.state.needsSetup ) {
            var fragLoc = queryString.parse(location.search)
            var error

            if ( fragLoc.error ) {
                error = E('div', { className: 'uk-alert uk-alert-danger' },
                          fragLoc.error)
            }

            return [ E('p', null, 'Welcome to Kite!'),
                     E('p', null, 'You\'ll need to create a user for your new appliance'),
                     error,
                     E('form', { action: '/admin/setup?next=/login', method: 'POST' },
                       E('div', { className: 'uk-margin' },
                         E('div', { className: 'uk-inline uk-width-1-1' },
                           E('span', { className: 'uk-form-icon uk-form-icon-flip' },
                             E('i', { className: 'fa fa-user' })),
                           E('input', { className: 'uk-input uk-form-large', required: true,
                                        placeholder: 'Name', name: 'displayname', type: 'text', defaultValue: fragLoc.displayname }))),

                       E('div', { className: 'uk-margin' },
                         E('div', { className: 'uk-inline uk-width-1-1' },
                           E('span', { className: 'uk-form-icon uk-form-icon-flip' },
                             E('i', { className: 'fa fa-lock' })),
                           E('input', { className: 'uk-input uk-form-large', required: true,
                                        placeholder: 'Password', name: 'password', type: 'password' }))),

                       E('div', { className: 'uk-margin' },
                         E('div', { className: 'uk-inline uk-width-1-1' },
                           E('span', { className: 'uk-form-icon uk-form-icon-flip' },
                             E('i', { className: 'fa fa-lock' })),
                           E('input', { className: 'uk-input uk-form-large', required: true,
                                        placeholder: 'Password (again)', name: 'password_again', type: 'password' }))),

                       E('div', { className: 'uk-margin' },
                         E('button', { type: 'submit', className: 'uk-button uk-button-primary uk-button-large' }, 'Create'))) ]
        } else if ( this.state.personas ) {
            var passwordBox
            if ( this.state.selectedPersona ) {
                passwordBox = [
                    E('div', { className: 'uk-margin' },
                      E('div', { className: 'uk-inline uk-width-1-1' },
                        E('span', { className: 'uk-form-icon uk-form-icon-flip' },
                          E('i', {className: 'fa fa-lock'})),
                        E('input', { className: 'uk-input uk-form-large', required: true,
                                     placeholder: 'Password', name: 'password',
                                     type: 'password' }))),
                    E('div', { className: 'uk-margin' },
                        E('input', { type: 'hidden', value: this.state.selectedPersona,
                                     name: 'persona_id' }),
                      E('button', { type: 'submit', className: 'uk-button uk-button-primary uk-button-large' }, 'Log in'))
                ]
            }

            return E('form', { action: '/admin/login?next=/', method: 'POST' },
                     E('ul', { className: 'kite-persona-list' },
                       this.state.personas.map(
                           ({persona_id, persona}) =>
                               E('li', {key: persona_id, className: ((this.state.selectedPersona == persona_id) ? 'active' : null),
                                        onClick: () => { this.setState({selectedPersona: persona_id}) } },
                                 E('div', { className: 'kite-display-name' }, persona.display_name),
                                 E('div', { className: 'kite-persona-attrs'},
                                   persona.superuser ? [ E('i', { className: 'fa fa-fw fa-lock' }) ] : null,
                                   E('i', { className: 'fa fa-fw fa-pencil' }),
                                   E('i', { className: 'fa fa-fw fa-info-circle' }))))),
                     passwordBox)
        } else if ( this.state.error ) {
            return E('div', { className: 'uk-alert-danger' },
                     E('p', null, this.state.error))
        } else {
            return E('i', { className: 'fa fa-spin fa-3x fa-circle-o-notch' })
        }
    }
}

var mainDiv = document.getElementById('user-box')
ReactDom.render(E(Logins), mainDiv)
