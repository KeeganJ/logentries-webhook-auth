LogentriesWebhookAuthExpress = require './src/logentries-webhook-auth-express'

module.exports = (options) ->
  logentriesWebhookAuthExpress = new LogentriesWebhookAuthExpress options

  middleware = (request, response, next) ->
    logentriesWebhookAuthExpress.getFromAuthorizationHeader request
    {user, hash} = request.logentriesWebhookAuth ? {}
    return response.status(401).end() unless user?
    next()

  middleware
