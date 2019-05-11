import React from 'react';
import ReactDom from 'react-dom';
import { LoadingIndicator, Image } from 'intrustd/src/react.js';

import TransitionGroup from 'react-transition-group/TransitionGroup';
import CSSTransition from 'react-transition-group/CSSTransition';

import { ADMIN_URL, fa } from './Common';
import AvatarEditor from 'react-avatar-editor';
import Dropzone from 'react-dropzone';
import { HashRouter as Router,
         Route, Switch,
         Link, withRouter } from 'react-router-dom';

import './no-avatar.png';

const E = React.createElement;

const UserEditState = {
    EDITING: Symbol('EDITING'),
    CREATING: Symbol('CREATING'),
    UPDATING: Symbol('UPDATING'),
    SUCCESS: Symbol('SUCCESS')
}

export class UserTile extends React.Component {
    render() {
        var userUrl = `/users/${this.props.persona_id}`;

        return E('li', {className: 'media p-2 user-tile'},
                 E(Link, { to: userUrl },
                   E(Image, { src: `${ADMIN_URL}/personas/${this.props.persona_id}/avatar`,
                              className: 'align-self-center mr-3' })),
                 E('div', { className: 'media-body' },
                   E('h5', { className: 'mt-0' },
                     this.props.superuser ? fa('lock') : null,
                     E(Link, { to: userUrl },
                       this.props.user.display_name))))
    }
}

export class UserEdit extends React.Component {
    constructor() {
        super()

        this.state = { mode: UserEditState.EDITING, error: {},
                       avatarZoom: 2 }

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
        this.setState({mode: UserEditState.SUCCESS})

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
            mode = UserEditState.CREATING
            req = fetch(`${ADMIN_URL}/personas`,
                        { method: 'POST',
                          body: JSON.stringify(creationInfo),
                          headers: { 'Content-type': 'application/json' }})
        } else {
            mode = UserEditState.UPDATING
            req = fetch(`${ADMIN_URL}/personas/${this.props.user.persona_id}`,
                        { method: 'PUT',
                          body: JSON.stringify(creationInfo),
                          headers: { 'Content-type': 'application/json' }})
        }

        this.setState({mode: UserEditState.CREATING,
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
        case UserEditState.SUCCESS:
            error = E('div', { className: 'uk-alert uk-alert-success' },
                      'Successfully saved!')
            break

        case UserEditState.CREATING:
        case UserEditState.UPDATING:
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

        return [
            E('h2', null, this.props.user ? 'Edit User' : 'Add User'),

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

              E('div', { className: 'ml-3', style: { flex: 1 } },
                E('div', { className: 'form-group' },
                  E('label', null, 'Display Name'),
                  E('input', { type: 'text', name: 'displayname',
                               className: 'form-control ${displayNameClass}',
                               defaultValue: this.props.user ? this.props.user.persona.display_name : undefined,
                               ref: this.usernameRef,
                               placeholder: 'Display Name' })),

                E('div', { className: 'form-group' },
                  E('label', null, 'Password'),
                  E('input', { type: 'password', name: 'password',
                               ref: this.passwordRef,
                               className: `form-control {passwordClass}`,
                               placeholder: 'Password' })),

                E('div', { className: 'form-group' },
                  E('label', null, 'Password (again)'),
                  E('input', { type: 'password', name: 'password_again',
                               className: `form-control ${password2Class}`,
                               ref: this.password2Ref,
                               placeholder: 'Password (again)' })),

                E('div', { className: 'd-flex flex-row justify-content-end' },
                  E('button', { className: 'btn btn-default', type: 'button',
                                onClick: this.close.bind(this) },
                    'Cancel'),
                  E('button', { className: 'btn btn-primary', type: 'button',
                                onClick: this.save.bind(this) },
                    'Save'))))
        ]
    }
}

class UsersBase extends React.Component {
    constructor () {
        super()

        this.state = { users: null }
    }

    componentDidMount() {
        fetch(`${ADMIN_URL}/personas`,
              { method: 'GET', cache: 'no-store' })
            .then((r) => r.json())
            .then((users) => { this.setState({users}) })
            .catch((error) => { console.error("Error fetching personas", error); this.setState({error}) })
    }
}

export class Users extends UsersBase {

    render() {
        var users = E(CSSTransition, {key: 'loading', classNames: 'none', timeout: { enter: 0, exit: 0 }},
                      E('li', null, E(LoadingIndicator, { key: 'loading' })))

        if ( this.state.error ) {
            users = E(CSSTransition, {key: 'loading', classNames: 'none', timeout: { enter: 0, exit: 0}}, E('li', null, this.state.error))
        } else if ( this.state.users !== null ) {
            users =
                this.state.users.slice(0, 4).map(
                    (user) =>
                        E(CSSTransition, {timeout: {enter: 500, exit: 100},
                                          classNames: 'user-tile',
                                          key: user.persona_id},
                          E(UserTile, { user: user.persona,
                                        persona_id: user.persona_id })))
        }

        return E('section', {className: 'card users-container'},
                 E('header', {className: 'card-header'},
                   E('div', { className: 'btn-toolbar float-right',
                              role: 'toolbar' },
                     E('button', { className: 'btn btn-outline-primary',
                                   onClick: () => { this.setState({addUser: true}) }},
                       E('i', { className: 'fa fa-plus fa-fw'})),
                     ' ',
                     E(Link, { to: '/users', className: 'ml-3' },
                       'See all',
                       E('i', { className: 'fa fa-fw fa-caret-right' }))),
                   'Users'),
                 E('ul', { className: 'list-unstyled' },
                   E(TransitionGroup, {className: 'users'},
                     users)))
    }
}

class UsersListPage extends UsersBase {
    render () {
        if ( this.state.users ) {
            return [
                E('div', { className: 'row' },
                  E('div', { className: 'float-right btn-group' },
                    E(Link, { className: 'btn btn-outline-primary',
                              to: '/users/new' },
                      fa('plus'), ' Add User'))),

                E('ul', { className: 'list-unstyled' },
                     this.state.users.map((user) =>
                                          E(UserTile, { user: user.persona,
                                                        persona_id: user.persona_id })))
            ]
        } else
            return E(LoadingIndicator)
    }
}

class UserBase extends React.Component {
    constructor () {
        super()
        this.state = {}
    }

    componentDidMount() {
        fetch(`${ADMIN_URL}/personas/${this.props.persona_id}`,
              { method: 'GET',
                cache: 'no-store' })
            .then((r) => {
                if ( r.status != 200 )
                    return Promise.reject(`Invalid status: ${r.status}`)
                else
                    return r.json().then((user) => this.setState({user}))
            })
            .catch((error) => { this.setState({error}) })
    }

    render() {
        if ( this.state.error )
            return E('div', { className: 'alert alert-danger',
                              role: 'alert' },
                     this.state.error)
        else if ( this.state.user ) {
            return this.renderUser()
        } else
            return E(LoadingIndicator)
    }
}

class UserPage extends UserBase {
    renderUser() {
        return E('div', { className: 'container mt-3' },
                 E('div', { className: 'row' },
                   E('div', { className: 'col-md-1' },
                     E(Image, { src: `${ADMIN_URL}/personas/${this.props.persona_id}/avatar` })),
                   E('div', { className: 'col-md-11' },
                     E('h4', null, this.state.user.persona.display_name))),
                 E('div', null,
                   E(Link, { to: `/users/${this.props.persona_id}/edit` },
                     fa('pencil'), ' Edit Profile')))
    }
}

class UserEditPageNoRoute extends UserBase {
    renderUser() {
        return E(UserEdit, { user: this.state.user,
                             onClose: () => this.props.history.push(`/users/${this.props.persona_id}`),
                             onAddUser: () => this.props.history.push(`/users/${this.props.persona_id}`) })
    }
}

var UserEditPage = withRouter(UserEditPageNoRoute)

export class UsersPage extends React.Component {
    render () {
        return [
            E(Route, { path: '/users', exact: true,
                       render: () => E(UsersListPage) }),

            E(Route, { path: '/users/new', exact: true,
                       render: () => E(UserEdit,
                                       { onAddUser: (persona) => {
                                           this.state.users.splice(0, 0, persona)
                                       } }) }),

            E(Route, { path: '/users/:persona_id', exact: true,
                       render: ({match}) =>
                       E(UserPage, {persona_id: match.params.persona_id}) }),

            E(Route, { path: '/users/:persona_id/edit', exact: true,
                       render: ({match}) =>
                       E(UserEditPage, {persona_id: match.params.persona_id}) })
        ]
    }
}
