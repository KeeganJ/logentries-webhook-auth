import { Request } from 'express';

export interface ExpressRequest extends Request {
  logentriesWebhookAuth?: AuthData
}

export interface AuthData {
  user?: string,
  hash?: string
}
