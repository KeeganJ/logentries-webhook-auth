# Logentries Webhook Authentication Middleware for Express

[![CircleCI](https://circleci.com/gh/KeeganJ/logentries-webhook-auth.svg?style=svg)](https://circleci.com/gh/KeeganJ/logentries-webhook-auth)

Express middleware for logentries webhook api, written in typescript with types available.

[Logentries documentation on webhooks](https://docs.logentries.com/docs/webhookalert#section-authentication)

# Usage

```js
  const express = require('express');
  const bodyParser = require('body-parser');
  const logentriesWebhookAuth = require('logentries-webhook-auth');
  
  const app = express();

  // We need the full raw (currently encrypted) body available.
  app.use(bodyParser.raw());        

  app.use(logentriesWebhookAuth(
    // The password that you put in the logentries webhook.
    password: 'some-preshared-key', 
    // bodyParser.raw will put the data to 'body' by default.
    bodyParam: 'body'               
  ));

  // "user" is now available on request.logentriesWebhookAuth.user

  // Your routes here

  app.listen(3000);
```

# Development

- `npm install`   - Setup dependencies and build project
- `npm run build` - Build source files manually
- `npm test`      - Run tests

## Environment Variables

`ENABLE_LOGENTRIES_WEBHOOK_AUTH_LOGGING` : Enable logging from this middleware. For local development only, as this could log sensitive data.
