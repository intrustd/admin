import UIKit from 'uikit';

import React from 'react';
import ReactDom from 'react-dom';

import { ADMIN_URL } from './Common';
import AvatarEditor from 'react-avatar-editor';
import Dropzone from 'react-dropzone';

import './no-avatar.png';

const E = React.createElement;

const UserDialogState = {
    EDITING: Symbol('EDITING'),
    CREATING: Symbol('CREATING'),
    UPDATING: Symbol('UPDATING'),
    SUCCESS: Symbol('SUCCESS')
}

export class UserDialog extends React.Component {
    constructor() {
        super()

        this.state = { mode: UserDialogState.EDITING, error: {},
                       avatarZoom: 2 }

        this.modalRef = React.createRef()

        this.usernameRef = React.createRef()
        this.passwordRef = React.createRef()
        this.password2Ref = React.createRef()
        this.avatarEditorRef = React.createRef()
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

    onSuccess(persona) {
        this.setState({mode: UserDialogState.SUCCESS})

        if ( this.props.onAddUser )
            this.props.onAddUser(persona)

        if ( this.state.avatarImage && this.props.onAvatarUpdated )
            this.props.onAvatarUpdated()
    }

    getAvatarImage() {
        var img = this.avatarEditorRef.current.getImageScaledToCanvas()

        return new Promise((accept, reject) => {
            img.toBlob(accept, 'PNG')
        })
    }

    setAvatar() {
        return this.getAvatarImage().then((img) => {
            var fd = new FormData()
            fd.append('photo', img, 'avatar.png')

            fetch(`${ADMIN_URL}/personas/${this.props.user.persona_id}/avatar`,
                  { method: 'POST',
                    body: fd })
                .then((r) => {
                    if ( r.status == 200 )
                        return null
                    else
                        return Promise.reject(`Unknown status: ${r.status}`)
                })
                .catch((e) => {
                    this.setError(`Could not upload avatar: ${e}`)
                })
        })
    }

    save() {
        var isCreating = this.props.user === null

        if ( this.usernameRef.current.value.length == 0 ) {
            this.setState({ error: { message: "Display name required",
                                     displayNameError: true } })
        }

        if ( this.passwordRef.current.value != this.password2Ref.current.value ) {
            this.setState({ error: { message: "Passwords do not match",
                                     passwordError: true,
                                     password2Error: true } })
            return
        }

        var creationInfo = { display_name: this.usernameRef.current.value,
                             password: this.passwordRef.current.value }
        var req, mode

        if ( creationInfo.password.length == 0 ) {
            if ( isCreating ) {
                this.setState({ error: { message: "Password required",
                                         passwordError: true,
                                         password2Error: true } })
                return
            } else
                delete creationInfo.password
        }

        if ( isCreating ) {
            mode = UserDialogState.CREATING
            req = fetch(`${ADMIN_URL}/personas`,
                        { method: 'POST',
                          body: JSON.stringify(creationInfo),
                          headers: { 'Content-type': 'application/json' }})
        } else {
            mode = UserDialogState.UPDATING
            req = fetch(`${ADMIN_URL}/personas/${this.props.user.persona_id}`,
                        { method: 'PUT',
                          body: JSON.stringify(creationInfo),
                          headers: { 'Content-type': 'application/json' }})
        }

        this.setState({mode: UserDialogState.CREATING,
                       error: {} })

        req.then((r) => {
                if ( r.status == 200 )
                    return r.json().then((persona) => {
                        if ( this.state.avatarImage )
                            this.setAvatar().then(() =>  this.onSuccess(persona))
                        else
                            this.onSuccess(persona)
                    })
                else {
                    return r.json().then(({error}) => {
                        if ( error == undefined )
                            this.setError("Unknown error")
                        else
                            this.setError(error)
                    })
                }
            })
            .catch((e) => {
                this.setError(`Got error: ${e}`)
            })
    }

    handleAvatarDrop(dropped) {
        this.setState({avatarImage: dropped[0]})
    }

    render () {
        var passwordClass, password2Class, displayNameClass, error

        if ( this.state.error.passwordError )
            passwordClass = 'uk-form-danger'

        if ( this.state.error.password2Error )
            password2Class = 'uk-form-danger'

        if ( this.state.error.displayNameError )
            displayNameClass = 'uk-form-danger'

        switch ( this.state.mode ) {
        case UserDialogState.SUCCESS:
            error = E('div', { className: 'uk-alert uk-alert-success' },
                      'Successfully saved!')
            break

        case UserDialogState.CREATING:
        case UserDialogState.UPDATING:
            error = E('div', { className: 'uk-alert uk-alert-primary' },
                      E('i', { className: 'fa fa-fw fa-2x fa-spin fa-circle-o-notch'}),
                      ' Saving...')
            break

        default:
            break;
        }

        if ( this.state.error.message )
            error = E('div', { className: 'uk-alert uk-alert-danger' },
                      this.state.error.message)

        return E('div', { className: 'uk-modal-group uk-modal uk-open',
                          style: { display: 'block' },
                          ref: this.modalRef },
                 E('div', { className: 'uk-modal-dialog' },
                   E('button', { className: 'uk-modal-close-default',
                                 type: 'button', onClick: this.close.bind(this) }),
                   E('div', { className: 'uk-modal-header' },
                     E('h2', { className: 'uk-modal-title' },
                       this.props.user ? 'Edit User' : 'Add User')),

                   E('div', { className: 'uk-modal-body' },

                     error,

                     E('div', { className: 'user-dialog-body' },
                       E(Dropzone, { onDrop: this.handleAvatarDrop.bind(this),
                                     disableClick: true,
                                     multiple: false,
                                     style: {width: '64px', height: '64px'} },
                         ({getRootProps, getInputProps}) =>
                         E('div', { className: 'avatar-form' },
                           E('label', null, 'Select avatar'),
                           E('div', getRootProps(),
                             E('input', getInputProps()),
                             E('input', { type: 'range',
                                          min: 1, max: 20,
                                          step: "0.01",
                                          onMouseDown: (e) => e.stopPropagation(),
                                          onMouseUp: (e) => e.stopPropagation(),
                                          onClick: (e) => e.stopPropagation(),
                                          value: this.state.avatarZoom,
                                          onChange: (e) => { console.log("Got change", e, e.target.value);
                                                             this.setState({avatarZoom: parseFloat(e.target.value)}) } }),
                             E(AvatarEditor, { width: 64, height: 64,
                                               border: 100,
                                               color: [255, 255, 255, 0.5],
                                               scale: this.state.avatarZoom,
                                               rotate: 0,
                                               ref: this.avatarEditorRef,
                                               image: this.state.avatarImage ? this.state.avatarImage : 'images/no-avatar.png' })))
                        ),

                       E('div', { className: 'uk-form-stacked' },
                         E('div', null,
                           E('label', { className: 'uk-form-label' }, 'Display Name'),
                           E('div', { className: 'uk-form-controls' },
                             E('input', { type: 'text', name: 'displayname',
                                          className: 'uk-input ${displayNameClass}',
                                          defaultValue: this.props.user ? this.props.user.persona.display_name : undefined,
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
                                          placeholder: 'Password (again)' })))))),

                   E('div', { className: 'uk-modal-footer uk-text-right' },
                     E('button', { className: 'uk-button uk-button-default', type: 'button',
                                   onClick: this.close.bind(this) },
                       'Cancel'),
                     E('button', { className: 'uk-button uk-button-primary',
                                   onClick: this.save.bind(this) },
                       'Save'))))
    }
}
