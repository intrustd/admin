// Webpack config for local (appliance) admin
const merge = require('webpack-merge')
const common = require('./webpack.common.js')
const HtmlWebpackPlugin = require('html-webpack-plugin')
const path = require('path')

module.exports = merge(common, {
    mode: 'development',
    entry: {
        'index': './src/LocalAdmin.js',
        'login': './src/LocalLogin.js'
    },
    plugins: [
        new HtmlWebpackPlugin({
            filename: 'login.html',
            template: '!!handlebars-loader!src/login.hbs',
            hash: true,
            scripts: [ "login.js" ],
            links: [ "index.css" ],
            title: "Intrustd Login",
            chunks: [ 'login' ]
        })
    ],
    output: {
        path: path.resolve(__dirname, 'dist-local')
    }
})

