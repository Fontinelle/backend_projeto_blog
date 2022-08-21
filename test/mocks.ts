import jwt from 'jsonwebtoken';
import 'dotenv/config';

const secret = String(process.env.SECRET);

const adminMock = {
  id: 1,
  name: 'any_user1',
  email: 'any1@email.com',
  password: 'Any#1&46',
  passwordLogin: 'Any#1&46',
  confirmPasswordLogin: 'Any#1&46',
  token: '',
  admin: true,
};

const userMock2 = {
  id: 2,
  name: 'any_user2',
  email: 'any2@email.com',
  password: '',
  passwordLogin: 'Any#1&46',
  confirmPasswordLogin: 'Any#1&46',
  token: '',
  admin: false,
};

const userMock3 = {
  name: 'any_user3',
  email: 'any3@email.com',
  password: 'Any#1&46',
  confirmPassword: 'Any#1&46',
  admin: true,
};

const id = 7;
const email = 'any@email.com';

const invalidUserToken = jwt.sign({ id, email }, secret, { expiresIn: process.env.TOKEN_EXPIRATION });

export { adminMock, userMock2, userMock3, invalidUserToken };
