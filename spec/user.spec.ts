import { fastify as appInstance } from '../src/index';
import type { FastifyInstance } from 'fastify';
import type { Pool, QueryResult } from 'pg';
import supertest from 'supertest';
import * as bcrypt from 'bcryptjs';

interface AuthenticatedUser {
  id: string;
  username: string;
}

interface UserBookParams {
  userId: string;
  bookId: string;
}

interface BookRequestBody {
  title: string;
  author: string;
}

jest.mock('pg', () => {
  const mPool = {
    query: jest.fn(), 
  };
  return { Pool: jest.fn(() => mPool) };
});

describe('User API', () => {
  let pool: jest.Mocked<Pool>;
  let fastify: FastifyInstance;

  beforeAll(async () => {
    pool = require('pg').Pool(); 
    fastify = appInstance; 
    await fastify.ready(); 
  });

  afterAll(async () => {
    await fastify.close(); 
  });

  beforeEach(() => {
    jest.clearAllMocks(); 
  });

  test('POST /users - success', async () => {
    const plainPassword = 'password1234';
    const hashedPassword = await bcrypt.hash(plainPassword, 10); 

    pool.query.mockImplementationOnce(() =>
      Promise.resolve({
        rowCount: 0, // Simulate no user found
        rows: [],
        command: '',
        oid: 0,
        fields: [],
      } as QueryResult<any>)
    );

    pool.query.mockImplementationOnce((query, values: [string, string, string]) => {
      const [id, username, password] = values;
      expect(username).toBe('testuser23');
      expect(bcrypt.compareSync(plainPassword, password)).toBe(true);
      return Promise.resolve({
        rowCount: 1,
        rows: [],
        command: '',
        oid: 0,
        fields: [],
      } as QueryResult<any>);
    });

    const response = await supertest(fastify.server)
      .post('/users')
      .send({ username: 'testuser23', password: plainPassword })
      .expect(201);

    expect(response.body).toEqual({
      id: expect.any(String),
      username: 'testuser23',
    });
  });

  test('POST /users - failure due to existing user', async () => {
    pool.query.mockImplementationOnce(() =>
      Promise.resolve({
        rowCount: 1, 
        rows: [],
        command: '',
        oid: 0,
        fields: [],
      } as QueryResult<any>)
    );

    const response = await supertest(fastify.server)
      .post('/users')
      .send({ username: 'testuser', password: 'password1234' })
      .expect(400);

    expect(response.body).toEqual({ error: 'Username already exists' });
  });

  test('POST /users/authenticate - success', async () => {
    const plainPassword = 'password1234';
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    pool.query.mockImplementationOnce(() =>
      Promise.resolve({
        rowCount: 1, // User exists
        rows: [{ id: 'user123', username: 'testuser', password: hashedPassword }],
        command: '',
        oid: 0,
        fields: [],
      } as QueryResult<any>)
    );

    const response = await supertest(fastify.server)
      .post('/users/authenticate')
      .send({ username: 'testuser', password: plainPassword })
      .expect(200);

    expect(response.body).toHaveProperty('token');
  });

  test('POST /users/authenticate - failure due to invalid credentials', async () => {
    pool.query.mockImplementationOnce(() =>
      Promise.resolve({
        rowCount: 1, 
        rows: [{ id: 'user123', username: 'testuser', password: 'hashedPassword' }],
        command: '',
        oid: 0,
        fields: [],
      } as QueryResult<any>)
    );

    const response = await supertest(fastify.server)
      .post('/users/authenticate')
      .send({ username: 'testuser', password: 'wrongpassword' })
      .expect(400);

    expect(response.body).toEqual({ error: 'Invalid credentials' });
  });

  test('POST /books - success', async () => {
    jest.spyOn(fastify.jwt, 'verify').mockResolvedValueOnce({ id: 'user123' });

    pool.query.mockImplementationOnce((query, values) => {
      const [bookId, title, author] = values as [string, string, string];
      expect(title).toBe('The Great Gatsby');
      expect(author).toBe('F. Scott Fitzgerald');
      return Promise.resolve({
        rowCount: 1,
        rows: [],
      });
    });

    const validToken = fastify.jwt.sign({ id: 'user123' });

    const response = await supertest(fastify.server)
      .post('/books')
      .set('Authorization', `Bearer ${validToken}`) 
      .send({ title: 'The Great Gatsby', author: 'F. Scott Fitzgerald' })
      .expect(201); 

    expect(response.body).toEqual({
      id: expect.any(String), 
      title: 'The Great Gatsby',
      author: 'F. Scott Fitzgerald',
    });
  });

  test('POST /users/:userId/books/:bookId - success', async () => {
    jest.spyOn(fastify.jwt, 'verify').mockResolvedValueOnce({ id: 'user123' });

    pool.query.mockImplementationOnce((query, values) => {
      const [userId, bookId] = values as [string, string];
      expect(userId).toBe('user123');
      expect(bookId).toBe('book123');
      return Promise.resolve({
        rowCount: 1,
        rows: [],
        command: '',
        oid: 0,
        fields: [],
      });
    });

    const validToken = fastify.jwt.sign({ id: 'user123' });

    const response = await supertest(fastify.server)
      .post('/users/user123/books/book123')
      .set('Authorization', `Bearer ${validToken}`)
      .expect(200);

    expect(response.body).toEqual({ message: 'Book attached successfully' });
  });

  test('POST /users/:userId/books/:bookId - failure due to unauthorized action', async () => {

    jest.spyOn(fastify.jwt, 'verify').mockResolvedValueOnce({ id: 'user456' }) ;


    const validToken = fastify.jwt.sign({ id: 'user456' });

    const response = await supertest(fastify.server)
      .post('/users/user123/books/book123')
      .set('Authorization', `Bearer ${validToken}`)
      .expect(403);

    expect(response.body).toEqual({ error: 'Forbidden' });
  });
});
