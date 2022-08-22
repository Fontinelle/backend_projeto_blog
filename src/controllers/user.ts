import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import 'dotenv/config';

const secret = String(process.env.SECRET);

interface IReq extends Request {
  payload?: {
    admin: boolean;
  };
}

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

const save = async (req: IReq, res: Response) => {
  const { name, email, password, confirmPassword } = req.body;
  let { admin } = req.body;
  if (password !== confirmPassword) return res.status(400).json({ errors: 'Confirmação de Senha inválida' });

  if (!req.originalUrl.startsWith('/users')) admin = false;
  if (!req.payload || !req.payload.admin) admin = false;

  try {
    const userExists = await User.findOne({ where: { email } });
    if (userExists) return res.status(422).json({ errors: 'Um usuário já foi cadastrada com esse e-mail' });

    const salt = await bcrypt.genSaltSync(12);
    const passwordHash = await bcrypt.hashSync(password, salt);

    const user = await User.create({ name, email, password: passwordHash, admin });

    return res.status(201).json({
      user: { id: user.id, name: user.name, email: user.email, admin: user.admin },
    });
  } catch (e) {
    return res.status(500).json({ errors: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
};

const findAll = async (req: Request, res: Response) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'name', 'email', 'admin'],
      where: { deleted: false },
    });
    return res.status(200).json({ users });
  } catch (e) {
    return res.status(500).json({ errors: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
};

const findOneById = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const user = await User.findOne({ where: { id }, attributes: ['id', 'name', 'email', 'admin'] });
    if (!user) return res.status(422).json({ errors: 'Usuário não encontrado' });

    return res.status(200).json({ user });
  } catch (e) {
    return res.status(500).json({ errors: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
};

const update = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { name, email, admin, password, confirmPassword } = req.body;

  if (password !== confirmPassword) return res.status(400).json({ errors: 'Confirmação de Senha inválida' });

  try {
    const userExists = await User.findOne({
      where: { id },
      attributes: ['id', 'name', 'email', 'admin'],
    });
    if (!userExists) return res.status(422).json({ errors: 'Usuário não encontrado' });

    if (userExists.email === email) return res.status(422).json({ errors: 'Um usuário já foi cadastrada com esse e-mail' });

    let passwordHash;
    if (password) {
      const salt = await bcrypt.genSaltSync(12);
      passwordHash = await bcrypt.hashSync(password, salt);
    }

    const user = await userExists.update({ name, email, admin, password: passwordHash });

    return res.status(201).json({ user });
  } catch (e) {
    return res.status(500).json({ errors: 'Aconteceu um erro no servidor, tente novamente mais tarde!' });
  }
};

export default { signIn, save, findAll, findOneById, update };
