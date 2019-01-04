import UIKit from 'uikit';

import React from 'react';
import ReactDom from 'react-dom';

const E = React.createElement;

const UserDialogState = {
    EDITING: Symbol('EDITING'),
    CREATING: Symbol('CREATING'),
    SUCCESS: Symbol('SUCCESS')
}

export class UserDialog extends React.Component {
    constructor() {
        super()

        this.state = { mode: UserDialogState.EDITING, error: {} }

        this.modalRef = React.createRef()

        this.usernameRef = React.createRef()
        this.passwordRef = React.createRef()
        this.password2Ref = React.createRef()
    }

    componentDidMount () {
    }

    componentWillUnmount() {
    }

    close() {
        this.props.onClose()
    }

    setError(error) {
        this.setState({error: { message: error,
                                passwordError: false,
                                password2Error: false }})
    }

    save() {
        if ( this.passwordRef.current.value != this.password2Ref.current.value ) {
            this.setState({ error: { message: "Passwords do not match",
                                     passwordError: true,
                                     password2Error: true } })
        }

        var creationInfo = { display_name: this.usernameRef.current.value,
                             password: this.passwordRef.current.value }

        this.setState({mode: UserDialogState.CREATING,
                       error: {} })

        fetch('kite+app://admin.flywithkite.com/personas',
              { method: 'POST',
                body: JSON.stringify(creationInfo),
                headers: { 'Content-type': 'application/json' }})
            .then((r) => {
                if ( r.status == 200 )
                    r.json().then((persona) => {
                        this.setState({mode: UserDialogState.SUCCESS})
                        if ( this.props.onAddUser )
                            this.props.onAddUser(persona)
                    })
                else {
                    r.json().then(({error}) => {
                        if ( error == undefined )
                            this.setError("Unknown error")
                        else
                            this.setError(error)
                    })
                }
            })
    }

    render () {
        var passwordClass, password2Class, error

        if ( this.state.error.passwordError )
            passwordClass = 'uk-form-danger'

        if ( this.state.error.password2Error )
            password2Class = 'uk-form-danger'

        if ( this.state.error.message )
            error = E('div', { className: 'uk-alert uk-alert-danger' },
                      this.error.message)

        return E('div', { className: 'uk-modal-group uk-modal uk-open',
                          style: { display: 'block' },
                          ref: this.modalRef },
                 E('div', { className: 'uk-modal-dialog' },
                   E('button', { className: 'uk-modal-close-default',
                                 type: 'button', onClick: this.close.bind(this) }),
                   E('div', { className: 'uk-modal-header' },
                     E('h2', { className: 'uk-modal-title' },
                       'Add User')),

                   E('div', { className: 'uk-modal-body uk-form-stacked' },

                     error,

                     E('div', null,
                       E('label', { className: 'uk-form-label' }, 'Display Name'),
                       E('div', { className: 'uk-form-controls' },
                         E('input', { type: 'text', name: 'displayname',
                                      className: 'uk-input',
                                      ref: this.usernameRef,
                                      placeholder: 'Display Name' }))),

                     E('div', null,
                       E('label', { className: 'uk-form-label' }, 'Password'),
                       E('div', { className: 'uk-form-controls' },
                         E('input', { type: 'password', name: 'password',
                                      ref: this.passwordRef,
                                      className: `uk-input ${passwordClass}`,
                                      placeholder: 'Password' }))),

                     E('div', null,
                       E('label', { className: 'uk-form-label' }, 'Password (again)'),
                       E('div', { className: 'uk-form-controls' },
                         E('input', { type: 'password', name: 'password_again',
                                      className: `uk-input ${password2Class}`,
                                      ref: this.password2Ref,
                                      placeholder: 'Password (again)' })))),

                   E('div', { className: 'uk-modal-footer uk-text-right' },
                     E('button', { className: 'uk-button uk-button-default', type: 'button',
                                   onClick: this.close.bind(this) },
                       'Cancel'),
                     E('button', { className: 'uk-button uk-button-primary',
                                   onClick: this.save.bind(this) },
                       'Save'))))
    }
}
