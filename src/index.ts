import Fastify from 'fastify';
import { Pool } from 'pg';
import { randomUUID } from 'crypto';
import * as bcrypt from 'bcryptjs';
import fastifyJwt from '@fastify/jwt';

const fastify = Fastify({ logger: true });

const secretKey = process.env.SECRET_KEY;
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const pool = new Pool({ connectionString: databaseUrl });

async function createTables(pool: Pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS books (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      author TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_books (
      user_id TEXT REFERENCES users(id),
      book_id TEXT REFERENCES books(id),
      PRIMARY KEY (user_id, book_id)
    );
  `);
}

fastify.register(fastifyJwt, { secret: process.env.SECRET_KEY as string });

interface UserRequestBody {
  username: string;
  password: string;
}

interface UserAuthResponse {
  token?: string; 
  error?: string;
}

interface BookRequestBody {
  title: string;
  author: string;
}
interface AuthenticatedUser {
  id: string;
  username: string;
}

interface UserBookParams {
  userId: string;
  bookId: string;
}

fastify.post<{ Body: UserRequestBody }>('/users', async (request, reply) => {
  const { username, password } = request.body;

  const { rowCount } = await pool.query('SELECT * FROM users WHERE username = $1;', [username]);
  if (rowCount && rowCount > 0) {
    return reply.status(400).send({ error: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const id = randomUUID();

  await pool.query('INSERT INTO users (id, username, password) VALUES ($1, $2, $3);', [id, username, hashedPassword]);
  return reply.status(201).send({ id, username });
});

fastify.post<{ Body: UserRequestBody, Reply: UserAuthResponse }>('/users/authenticate', async (request, reply) => {
  const { username, password } = request.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1;', [username]);
  const user = rows[0];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return reply.status(400).send({ error: 'Invalid credentials' });
  }

  const token = fastify.jwt.sign({ id: user.id, username: user.username });
  return reply.send({ token });
});

fastify.post<{ Body: BookRequestBody }>('/books', async (request, reply) => {
  try {
    await request.jwtVerify();
    const { title, author } = request.body;
    const bookId = randomUUID();

    await pool.query('INSERT INTO books (id, title, author) VALUES ($1, $2, $3);', [bookId, title, author]);
    return reply.status(201).send({ id: bookId, title, author });
  } catch (err) {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
});

fastify.post<{ Params: UserBookParams }>('/users/:userId/books/:bookId', async (request, reply) => {
  try {
    await request.jwtVerify();

    // Use type assertion to specify the type of request.user
    const user = request.user as AuthenticatedUser;
    const { userId, bookId } = request.params; // Typed as UserBookParams

    if (user.id !== userId) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    await pool.query('INSERT INTO user_books (user_id, book_id) VALUES ($1, $2);', [userId, bookId]);
    return reply.send({ message: 'Book attached successfully' });
  } catch (err) {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
});

async function bootstrap() {
  try {
    await createTables(pool);
    await fastify.ready();   
    await fastify.listen({ port: 3000, host: '0.0.0.0' });
    console.log('Server started on http://localhost:3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);          
  }
}

// Start the server
bootstrap();

export { fastify };
