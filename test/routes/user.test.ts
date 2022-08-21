import supertest from 'supertest';
import app from '../../src/app';
import db from '../../src/config/database';
import User from '../../src/models/User';
import bcrypt from 'bcrypt';
import { adminMock, invalidUserToken, userMock2, userMock3 } from '../mocks';

const request = supertest(app);

describe('User', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';

    await db.sync({ force: true });
    const salt = await bcrypt.genSaltSync(12);
    adminMock.password = await bcrypt.hashSync('Any#1&46', salt);
    userMock2.password = await bcrypt.hashSync('Any#1&46', salt);

    await User.create(adminMock);
    await User.create(userMock2);
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
      const result = await request.post('/signin').send({ email: userMock2.email, password: '1234567' });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Senha inválida'] });
    });

    it('should log in with user email and password', async () => {
      const result = await request.post('/signin').send({ email: userMock2.email, password: userMock2.passwordLogin });

      userMock2.token = result.body.token;
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

  describe('Save', () => {
    it('should require login with token', async () => {
      const result = await request.post('/users');

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['É necessário fazer login'] });
    });

    it('should have a valid token', async () => {
      const result = await request.post('/users').set({
        authorization: `bearer invalid.Token`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Token expirado ou inválido'] });
    });

    it('should have a valid user token', async () => {
      const result = await request.post('/users').set({
        authorization: `bearer ${invalidUserToken}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário inválido'] });
    });

    it('should not allow non-admin user', async () => {
      const result = await request.post('/users').set({
        authorization: `bearer ${userMock2.token}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário não é administrador'] });
    });

    it('should not register user without passing all information', async () => {
      const result = await request
        .post('/users')
        .send({})
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: [
          'O nome deve ter no mínimo 3 caracteres',
          'Não é um email válido',
          'A senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos',
          'A confirmação de senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos',
        ],
      });
    });

    it('should not register unnamed user', async () => {
      const result = await request
        .post('/users')
        .send({
          email: userMock3.email,
          password: userMock3.password,
          confirmPassword: userMock3.confirmPassword,
        })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({ errors: ['O nome deve ter no mínimo 3 caracteres'] });
    });

    it('should not register user without email', async () => {
      const result = await request
        .post('/users')
        .send({
          name: userMock3.name,
          password: userMock3.password,
          confirmPassword: userMock3.confirmPassword,
        })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({ errors: ['Não é um email válido'] });
    });

    it('should not register user without password', async () => {
      const result = await request
        .post('/users')
        .send({ name: userMock3.name, email: userMock3.email })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: [
          'A senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos',
          'A confirmação de senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos',
        ],
      });
    });

    it('should not register user without password confirmation', async () => {
      const result = await request
        .post('/users')
        .send({ name: userMock3.name, email: userMock3.email, password: userMock3.password })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: ['A confirmação de senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos'],
      });
    });

    it('should not register user if password confirmation is different from password', async () => {
      const result = await request
        .post('/users')
        .send({
          name: userMock3.name,
          email: userMock3.email,
          password: userMock3.password,
          confirmPassword: 'Any#1&48',
        })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: 'Confirmação de Senha inválida',
      });
    });

    it('should register user successfully', async () => {
      const result = await request
        .post('/users')
        .send({
          name: userMock3.name,
          email: userMock3.email,
          password: userMock3.password,
          confirmPassword: userMock3.confirmPassword,
          admin: userMock3.admin,
        })
        .set({
          authorization: `bearer ${adminMock.token}`,
        });

      expect(result.statusCode).toBe(201);
      expect(result.body).toMatchObject({
        user: {
          id: 3,
          name: 'any_user3',
          email: 'any3@email.com',
          admin: true,
        },
      });
      expect(result.body).not.toHaveProperty('password');
    });

    it('should store encrypted password', async () => {
      const email = userMock3.email;
      const result = await User.findOne({ where: { email } });

      expect(result?.password).not.toBeUndefined();
      expect(result?.password).not.toBe(userMock3.password);
    });

    it('should not register user with e-mail already registered', async () => {
      const result = await request
        .post('/users')
        .send({
          name: userMock3.name,
          email: userMock3.email,
          password: userMock3.password,
          confirmPassword: userMock3.confirmPassword,
        })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(422);
      expect(result.body).toMatchObject({ errors: 'Um usuário já foi cadastrada com esse e-mail' });
    });
  });
});
