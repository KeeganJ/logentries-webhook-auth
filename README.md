# Express Logentries Webhook Authentication Middleware
Express middleware for logentries webhook api

### Example:
```js
  var express = require('express');
  var logentriesWebhookAuth = require('express-logentries-webhook-auth');
  var app = express();

  app.use(logentriesWebhookAuth(
    password: 'some-preshared-key',
    bodyParam: 'rawBody'
  ));
  app.use(function (request, response) {
    response.json({uuid: request.logentriesWebhookAuth.user});
  });
  app.listen(3333);
```
