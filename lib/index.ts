import { Authorizer } from './authorizer';
import { ExpressRequest } from './interfaces';

export default function(password: string) {
  const authorizer = new Authorizer(password);

  const middleware = function(request: ExpressRequest, response: any, next) {
    authorizer.getFromAuthorizationHeader(request);
    const auth = request.logentriesWebhookAuth;

    if (!auth || !auth.user) {
      return response.status(401).end();
    }

    return next();
  };

  return middleware;
};
