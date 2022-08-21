import jwt from 'jsonwebtoken';
import User from '../models/User';
import 'dotenv/config';
import { NextFunction, Request, Response } from 'express';

const secret = String(process.env.SECRET);

interface IReq extends Request {
  payload?: {
    admin: boolean;
    id: number;
    email: string;
  };
}

const authenticate = async (req: IReq, res: Response, next: NextFunction) => {
  const { authorization } = req.headers;

  if (!authorization) {
    return res.status(401).json({ errors: ['É necessário fazer login'] });
  }

  const [, token] = authorization.split(' ');
  try {
    const data = JSON.stringify(jwt.verify(token, secret));

    const { id } = JSON.parse(data);

    const user = await User.findOne({ where: { id } });

    if (!user) return res.status(401).json({ errors: ['Usuário inválido'] });

    const { email, admin } = user;

    req.payload = { id, email, admin };

    return next();
  } catch (e) {
    return res.status(401).json({ errors: ['Token expirado ou inválido'] });
  }
};

export default authenticate;
