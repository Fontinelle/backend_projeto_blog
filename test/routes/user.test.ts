import supertest from 'supertest';
import app from '../../src/app';
import db from '../../src/config/database';
import User from '../../src/models/User';
import bcrypt from 'bcrypt';
import { adminMock, invalidUserToken, userMock2, userMock3, userMock4 } from '../mocks';

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

  describe('Signup', () => {
    it('should not register user without passing all information', async () => {
      const result = await request.post('/signup');

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
      const result = await request.post('/signup').send({
        email: userMock3.email,
        password: userMock3.password,
        confirmPassword: userMock3.confirmPassword,
      });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({ errors: ['O nome deve ter no mínimo 3 caracteres'] });
    });

    it('should not register user without email', async () => {
      const result = await request.post('/signup').send({
        name: userMock3.name,
        password: userMock3.password,
        confirmPassword: userMock3.confirmPassword,
      });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({ errors: ['Não é um email válido'] });
    });

    it('should not register user without password', async () => {
      const result = await request.post('/signup').send({ name: userMock3.name, email: userMock3.email });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: [
          'A senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos',
          'A confirmação de senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos',
        ],
      });
    });

    it('should not register user without password confirmation', async () => {
      const result = await request.post('/signup').send({ name: userMock3.name, email: userMock3.email, password: userMock3.password });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: ['A confirmação de senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos'],
      });
    });

    it('should not register user if password confirmation is different from password', async () => {
      const result = await request.post('/signup').send({
        name: userMock3.name,
        email: userMock3.email,
        password: userMock3.password,
        confirmPassword: 'Any#1&48',
      });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: 'Confirmação de Senha inválida',
      });
    });

    it('should register user successfully', async () => {
      const result = await request.post('/signup').send({
        name: userMock4.name,
        email: userMock4.email,
        password: userMock4.password,
        confirmPassword: userMock4.confirmPassword,
        admin: userMock4.admin,
      });

      expect(result.statusCode).toBe(201);
      expect(result.body).toMatchObject({
        user: {
          id: 4,
          name: 'any_user4',
          email: 'any4@email.com',
          admin: false,
        },
      });
      expect(result.body).not.toHaveProperty('password');
    });

    it('should store encrypted password', async () => {
      const email = userMock4.email;
      const result = await User.findOne({ where: { email } });

      expect(result?.password).not.toBeUndefined();
      expect(result?.password).not.toBe(userMock4.password);
    });

    it('should not register user with e-mail already registered', async () => {
      const result = await request.post('/signup').send({
        name: userMock4.name,
        email: userMock4.email,
        password: userMock4.password,
        confirmPassword: userMock4.confirmPassword,
      });

      expect(result.statusCode).toBe(422);
      expect(result.body).toMatchObject({ errors: 'Um usuário já foi cadastrada com esse e-mail' });
    });
  });

  describe('FindAll', () => {
    it('should require login with token', async () => {
      const result = await request.get('/users');

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['É necessário fazer login'] });
    });

    it('should have a valid token', async () => {
      const result = await request.get('/users').set({
        authorization: `bearer invalid.Token`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Token expirado ou inválido'] });
    });

    it('should have a valid user token', async () => {
      const result = await request.get('/users').set({
        authorization: `bearer ${invalidUserToken}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário inválido'] });
    });

    it('should not allow non-admin user', async () => {
      const result = await request.get('/users').set({
        authorization: `bearer ${userMock2.token}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário não é administrador'] });
    });

    it('should return all user', async () => {
      const result = await request.get('/users').set({
        authorization: `bearer ${adminMock.token}`,
      });

      expect(result.statusCode).toBe(200);
      expect(result.body.users).toHaveLength(4);
      expect(result.body).toMatchObject({
        users: [
          {
            admin: true,
            email: 'any1@email.com',
            id: 1,
            name: 'any_user1',
          },
          {
            admin: false,
            email: 'any2@email.com',
            id: 2,
            name: 'any_user2',
          },
          {
            admin: true,
            email: 'any3@email.com',
            id: 3,
            name: 'any_user3',
          },
          {
            admin: false,
            email: 'any4@email.com',
            id: 4,
            name: 'any_user4',
          },
        ],
      });
    });
  });

  describe('FindOneById', () => {
    it('should require login with token', async () => {
      const result = await request.get('/users/3');

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['É necessário fazer login'] });
    });

    it('should have a valid token', async () => {
      const result = await request.get('/users/3').set({
        authorization: `bearer invalid.Token`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Token expirado ou inválido'] });
    });

    it('should have a valid user token', async () => {
      const result = await request.get('/users/3').set({
        authorization: `bearer ${invalidUserToken}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário inválido'] });
    });

    it('should not allow non-admin user', async () => {
      const result = await request.get('/users/3').set({
        authorization: `bearer ${userMock2.token}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário não é administrador'] });
    });

    it('should return status 422 if no user found', async () => {
      const result = await request.get('/users/5').set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(422);
      expect(result.body).toMatchObject({ errors: 'Usuário não encontrado' });
    });

    it('should return status 400 if ID is invalid', async () => {
      const result = await request.get('/users/idInvalid').set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({ errors: ['Não é um ID válido'] });
    });

    it('should return one user', async () => {
      const result = await request.get('/users/3').set({
        authorization: `bearer ${adminMock.token}`,
      });

      expect(result.statusCode).toBe(200);
      expect(result.body).toMatchObject({
        user: {
          admin: true,
          email: 'any3@email.com',
          id: 3,
          name: 'any_user3',
        },
      });
    });
  });

  describe('Update', () => {
    it('should require login with token', async () => {
      const result = await request.put('/users/3');

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['É necessário fazer login'] });
    });

    it('should have a valid token', async () => {
      const result = await request.put('/users/3').set({
        authorization: `bearer invalid.Token`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Token expirado ou inválido'] });
    });

    it('should have a valid user token', async () => {
      const result = await request.put('/users/3').set({
        authorization: `bearer ${invalidUserToken}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário inválido'] });
    });

    it('should not allow non-admin user', async () => {
      const result = await request.put('/users/3').set({
        authorization: `bearer ${userMock2.token}`,
      });

      expect(result.statusCode).toBe(401);
      expect(result.body).toMatchObject({ errors: ['Usuário não é administrador'] });
    });

    it('should return status 422 if no user found', async () => {
      const result = await request.put('/users/7').set({
        authorization: `bearer ${adminMock.token}`,
      });

      expect(result.statusCode).toBe(422);
      expect(result.body).toMatchObject({ errors: 'Usuário não encontrado' });
    });

    it('should return status 400 if ID is invalid', async () => {
      const result = await request.put('/users/idInvalid').set({
        authorization: `bearer ${adminMock.token}`,
      });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({ errors: ['Não é um ID válido'] });
    });

    it('should update username', async () => {
      const result = await request
        .put('/users/3')
        .send({ name: 'name_update' })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(201);
      expect(result.body).toMatchObject({
        user: {
          name: 'name_update',
          email: userMock3.email,
          admin: true,
          id: 3,
        },
      });
      expect(result.body).not.toHaveProperty('password');
    });

    it('should not update user with e-mail already registered', async () => {
      const result = await request
        .put('/users/3')
        .send({ email: userMock3.email })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(422);
      expect(result.body).toMatchObject({ errors: 'Um usuário já foi cadastrada com esse e-mail' });
    });

    it('should update user email', async () => {
      const result = await request
        .put('/users/3')
        .send({ email: 'update@email.com' })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(201);
      expect(result.body).toMatchObject({
        user: {
          name: 'name_update',
          email: 'update@email.com',
          admin: true,
          id: 3,
        },
      });
      expect(result.body).not.toHaveProperty('password');
    });

    it('should update user admin status', async () => {
      const result = await request
        .put('/users/3')
        .send({ admin: false })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(201);
      expect(result.body).toMatchObject({
        user: {
          name: 'name_update',
          email: 'update@email.com',
          admin: false,
          id: 3,
        },
      });
      expect(result.body).not.toHaveProperty('password');
    });

    it('should not update user if password confirmation is different from password', async () => {
      const result = await request
        .put('/users/3')
        .send({ password: 'Any#1&48' })
        .set({ authorization: `bearer ${adminMock.token}` });

      expect(result.statusCode).toBe(400);
      expect(result.body).toMatchObject({
        errors: 'Confirmação de Senha inválida',
      });
    });

    it('should update user if password and password confirmation provided', async () => {
      const result = await request
        .put('/users/3')
        .send({ password: 'Any#1&48', confirmPassword: 'Any#1&48' })
        .set({ authorization: `bearer ${adminMock.token}` });

      const email = 'update@email.com';
      const user = await User.findOne({ where: { email } });

      expect(result.statusCode).toBe(201);
      expect(result.body).toMatchObject({
        user: {
          name: 'name_update',
          email: 'update@email.com',
          admin: false,
          id: 3,
        },
      });
      expect(result.body).not.toHaveProperty('password');
      expect(user?.password).not.toBeUndefined();
      expect(user?.password).not.toBe('Any#1&48');
    });
  });
});
