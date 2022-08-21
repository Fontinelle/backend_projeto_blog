import supertest from 'supertest';
import app from '../../src/app';
import db from '../../src/config/database';
import User from '../../src/models/User';
import bcrypt from 'bcrypt';
import { adminMock, userMock } from '../mocks';

const request = supertest(app);

describe('User', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';

    await db.sync({ force: true });
    const salt = await bcrypt.genSaltSync(12);
    adminMock.password = await bcrypt.hashSync('Any#1&46', salt);
    userMock.password = await bcrypt.hashSync('Any#1&46', salt);

    await User.create(adminMock);
    await User.create(userMock);
  });

  describe('Signin', () => {
    it('should not login if email and password are not provided', async () => {
      const result = await request.post('/signin').send({});

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Informe email e senha'] });
    });

    it('should not log in if email is not valid', async () => {
      const result = await request.post('/signin').send({ email: 'email', password: '1234567' });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário não encontrado'] });
    });

    it('should not log in if password is not valid', async () => {
      const result = await request.post('/signin').send({ email: userMock.email, password: '1234567' });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Senha inválida'] });
    });

    it('should log in with user email and password', async () => {
      const result = await request.post('/signin').send({ email: userMock.email, password: userMock.passwordLogin });

      userMock.token = result.body.token;
      expect(result.statusCode).toBe(200);
      expect(result.body).toMatchObject({
        user: {
          id: 2,
          name: 'any_user2',
          email: 'any2@email.com',
          admin: false,
        },
      });
      expect(result.body).toHaveProperty('token');
      expect(result.body).toHaveProperty('exp');
      expect(result.body).toHaveProperty('iat');
      expect(result.body).not.toHaveProperty('password');
    });

    it('should log in with admin email and password', async () => {
      const result = await request.post('/signin').send({ email: adminMock.email, password: adminMock.passwordLogin });

      adminMock.token = result.body.token;
      expect(result.statusCode).toBe(200);
      expect(result.body).toMatchObject({
        user: {
          id: 1,
          name: 'any_user1',
          email: 'any1@email.com',
          admin: true,
        },
      });
      expect(result.body).toHaveProperty('token');
      expect(result.body).toHaveProperty('exp');
      expect(result.body).toHaveProperty('iat');
      expect(result.body).not.toHaveProperty('password');
    });
  });
});
