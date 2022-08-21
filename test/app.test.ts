import supertest from 'supertest';
import app from '../src/app';

const request = supertest(app);

describe('App', () => {
  it.only('should respond on root', async () => {
    const result = await request.get('/');

    expect(result.statusCode).toBe(200);
    expect(result.body).toHaveProperty('ok', true);
  });
});
