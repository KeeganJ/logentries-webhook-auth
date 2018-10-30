import { Request } from 'express';

export interface ExpressRequest extends Request {
  logentriesWebhookAuth?: LogentriesWebhookAuth
}

export interface LogentriesWebhookAuth {
  user?: string,
  hash?: string
}
