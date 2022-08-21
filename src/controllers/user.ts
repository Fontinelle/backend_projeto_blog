import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import 'dotenv/config';

const secret = String(process.env.SECRET);

const signIn = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(401).json({ errors: ['Informe email e senha'] });
  }
  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(401).json({ errors: ['Usuário não encontrado'] });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ errors: ['Senha inválida'] });
    }

    const now = Math.floor(Date.now() / 1000);
    const { id, name, admin } = user;

    const token = jwt.sign({ id, email }, secret, {
      expiresIn: process.env.TOKEN_EXPIRATION,
    });
    return res.send({
      token,
      user: { id, name, email, admin },
      iat: now,
      exp: now + 60 * 60 * 24 * 3,
    });
  } catch (e) {
    return res.status(500).json({ errors: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
};

export default { signIn };
