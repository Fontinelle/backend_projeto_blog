import { Request, Response, NextFunction } from 'express';

interface IReq extends Request {
  payload?: { admin: boolean };
}

const admin = (req: IReq, res: Response, next: NextFunction) => {
  if (req.payload?.admin) {
    return next();
  } else {
    return res.status(401).json({ errors: ['Usuário não é administrador'] });
  }
};

export default admin;
