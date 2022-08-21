import { Request, Response, NextFunction } from 'express';
import { validationResult, ValidationError } from 'express-validator';

const validation = (req: Request, res: Response, next: NextFunction) => {
  const errorFormatter = ({ msg }: ValidationError) => msg;

  const errors = validationResult(req).formatWith(errorFormatter);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  return next();
};

export default validation;
