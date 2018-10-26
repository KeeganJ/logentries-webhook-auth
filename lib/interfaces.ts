import { Request } from 'express';

export interface AuthorizerOptions {
  bodyParam?: string,
  password?: string
}

export interface ExpressRequest extends Request {
  logentriesWebhookAuth?: LogentriesWebhookAuth
}

export interface LogentriesWebhookAuth {
  user?: string,
  hash?: string
}
