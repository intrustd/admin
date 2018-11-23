import React from 'react';
import { KiteUploadButton, KiteForm, KitePersonaButton } from 'stork-js/src/react.js';

const E = React.createElement;

export default class Navbar extends React.Component {
    constructor () {
        super()
        this.uploadRef = React.createRef()
    }

    doUpload(e) {
        if ( e ) e.preventDefault()
        this.props.uploadPhoto(this.uploadRef.current.formData)

        this.uploadRef.current.reset()
    }

    render() {
        return E('nav', {className: 'uk-navbar-container', 'uk-navbar': 'uk-navbar'},
                 E('div', {className: 'uk-navbar-left'},
                   E('a', {className: 'uk-navbar-item uk-logo',
                           href: '#'}, 'Admin')),

                 E('div', {className: 'uk-navbar-right'},
                   E('ul', {className: 'uk-navbar-nav'},
                     E(KitePersonaButton, {}))));
    }
}
