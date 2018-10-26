import { Authorizer } from './authorizer';
import { AuthorizerOptions, ExpressRequest } from './interfaces';

export default function(options: AuthorizerOptions) {
  const authorizer = new Authorizer(options);

  const middleware = function(request: ExpressRequest, response: any, next) {
    authorizer.getFromAuthorizationHeader(request);

    const auth = request.logentriesWebhookAuth || {};

    if (auth.user === null) {
      return response.status(401).end();
    }

    return next();
  };

  return middleware;
};
