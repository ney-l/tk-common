import { type Request, type Response, type NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import { type UserPayload } from '@/types';
import { BadRequestError, NotAuthorizedError } from '@/errors';
import env from '@/environments';

const verifyJwt = (token: string) => {
  return jwt.verify(token, env.JWT_SECRET);
};

export const attachCurrentUser = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.session?.jwt) {
    throw new BadRequestError('Missing Authentication Token.');
  }

  try {
    const payload = verifyJwt(req.session.jwt) as UserPayload;
    req.currentUser = payload;
  } catch (err) {
    throw new NotAuthorizedError();
  } finally {
    next();
  }
};
