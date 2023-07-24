import { type Request, type Response, type NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import { type UserPayload } from '@/types';
import { BadRequestError, NotAuthorizedError } from '@/errors';
import env from '@/environments';

const verifyJwt = (token: string) => {
  return jwt.verify(token, env.JWT_SECRET);
};

/**
 * Attach the current user to the request object
 * if the user is authenticated.
 * Otherwise, do nothing and just call next().
 */
export const attachCurrentUser = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.session?.jwt) {
    return next();
  }

  try {
    const payload = verifyJwt(req.session.jwt) as UserPayload;
    req.currentUser = payload;
  } catch (err) {
    next();
  }
};
