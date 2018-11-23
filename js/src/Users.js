import UIKit from 'uikit';

import React from 'react';
import ReactDom from 'react-dom';

const E = React.createElement;

export class UserDialog extends React.Component {
    constructor() {
        super()

        this.state = { }

        this.modalRef = React.createRef()
    }

    componentDidMount () {
        var modal = UIKit.modal(this.modalRef.current)
        modal.show()
    }

    close() {
        this.props.onClose()
    }

    render () {
        return E('div', { className: 'uk-modal-group',
                          ref: this.modalRef },
                 E('div', { className: 'uk-modal-dialog' },
                   E('button', { className: 'uk-modal-close-default',
                                 type: 'button', onClick: this.close.bind(this) }),
                   E('div', { className: 'uk-modal-header' },
                     E('h2', { className: 'uk-modal-title' },
                       'Add User')),

                   E('div', { className: 'uk-modal-body' },
                     'Body'),

                   E('div', { className: 'uk-modal-footer uk-text-right' },
                     E('button', { className: 'uk-button uk-button-default', type: 'button',
                                   onClick: this.close.bind(this) },
                       'Cancel'),
                     E('button', { className: 'uk-button uk-button-primary' }, 'Save'))))
    }
}
