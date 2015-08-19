_ = require 'lodash'
crypto = require 'crypto'

class LogentriesWebhookAuthExpress
  constructor: (@options={}, dependencies={}) ->

  getFromAuthorizationHeader: (request) =>
    return unless request.headers?
    parts = request.headers.authorization?.split(' ')
    return unless parts? && parts[0]?.toLocaleUpperCase() == 'LE'

    [user, hash] = parts[1].split(':')

    return unless @_checkHash request, hash

    request.logentriesWebhookAuth ?= {}
    request.logentriesWebhookAuth.user = _.trim user
    request.logentriesWebhookAuth.hash = hash

  _checkHash: (request, hash) =>
    content_md5 = crypto.createHash('md5').update(request.body).digest('base64')
    canonical = [
      'POST'
      request.get('Content-Type')
      content_md5
      request.get('Date')
      request.path
      request.get('X-Le-Nonce')
    ].join("\n")

    canonical_b64 = new Buffer(canonical).toString('base64')
    signature = crypto.createHmac('sha1', @options.password).update(canonical_b64).digest('base64')

    return signature == hash

module.exports = LogentriesWebhookAuthExpress
