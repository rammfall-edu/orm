import Fastify from 'fastify';
import { Client } from 'pg';
import { hash, compare } from 'bcrypt';
import { sign, verify } from 'jsonwebtoken';

const fastify = Fastify({
  logger: true,
});
const client = new Client({
  user: 'postgres',
  host: 'localhost',
  database: 'todo',
  password: 'postgres',
  port: 5556,
});
const SECRET = 'secret';

client.connect();

fastify.register(import('@fastify/cors'));
fastify.register(import('@fastify/multipart'), {
  addToBody: true,
});
fastify.register(import('@fastify/cookie'));

fastify.post(
  '/register',
  {
    schema: {
      body: {
        type: 'object',
        properties: {
          email: {
            type: 'string',
            minLength: 5,
            maxLength: 30,
          },
          password: {
            type: 'string',
            minLength: 8,
            maxLength: 50,
          },
        },
        required: ['email', 'password'],
      },
    },
  },
  async (request, reply) => {
    const { email, password } = request.body;
    const { rows } = await client.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    if (rows.length > 0) {
      return reply.code(400).send({
        error: 'Email already exists',
      });
    }

    await client.query('INSERT INTO users (email, password) VALUES ($1, $2)', [
      email,
      await hash(password, 10),
    ]);
    return reply.send({ info: 'success' });
  }
);

fastify.post(
  '/login',
  {
    schema: {
      body: {
        type: 'object',
        properties: {
          email: {
            type: 'string',
            minLength: 5,
            maxLength: 30,
          },
          password: {
            type: 'string',
            minLength: 8,
            maxLength: 50,
          },
        },
        required: ['email', 'password'],
      },
    },
  },
  async (request, reply) => {
    const { email, password } = request.body;

    const { rows } = await client.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (rows.length === 0) {
      return reply.code(400).send({
        error: 'Email does not exist',
      });
    }

    if (!(await compare(password, rows[0].password))) {
      return reply.code(400).send({
        error: 'Password is incorrect',
      });
    }

    const user = rows[0];
    const token = await sign({ email, id: user.id }, SECRET, {
      expiresIn: '24h',
    });

    return reply
      .setCookie('token', token, { httpOnly: true })
      .send({ info: 'success' });
  }
);

fastify.register(async (server, opts, next) => {
  server.addHook('onRequest', async (request, reply) => {
    try {
      const user = await verify(request.cookies.token, SECRET);
      request.id = user.id;
    } catch (err) {
      return reply.code(401).send({
        error: 'Unauthorized',
      });
    }
  });

  server.get('/projects', async (request, reply) => {
    const { id } = request;
    const { rows } = await client.query(
      'SELECT * FROM projects WHERE userid = $1',
      [id]
    );
    return reply.send(rows);
  });

  server.post(
    '/projects',
    {
      schema: {
        body: {
          type: 'object',
          properties: {
            topic: {
              type: 'string',
              minLength: 5,
              maxLength: 20,
            },
            name: {
              type: 'string',
              minLength: 5,
              maxLength: 30,
            },
          },
          required: ['name'],
        },
      },
    },
    async (request, reply) => {
      const {
        id,
        body: { name, topic },
      } = request;
      await client.query(
        'INSERT INTO projects (name, topic, userid) VALUES($1, $2, $3);',
        [name, topic, id]
      );
      const { rows } = await client.query(
        'SELECT * FROM projects WHERE userid = $1;',
        [id]
      );

      return reply.send(rows);
    }
  );

  server.delete('/projects/:projectId', async (request, reply) => {
    const {
      id,
      params: { projectId },
    } = request;
    await client.query('DELETE FROM projects where id = $1 AND userid = $2;', [
      projectId,
      id,
    ]);

    reply.send({ info: 'success' });
  });

  server.get('/projects/:projectId/tasks', async (request, reply) => {
    const {
      id,
      params: { projectId },
    } = request;
    const { rows: projects } = await client.query(
      'SELECT * FROM projects WHERE id = $1 AND userid = $2',
      [projectId, id]
    );
    if (!projects.length) {
      return reply.status(403).send('Go away');
    }

    const { rows: tasks } = await client.query(
      'SELECT * FROM tasks WHERE projectid = $1',
      [projectId]
    );

    return reply.send(tasks);
  });

  server.post('/projects/:projectId/tasks', async (request, reply) => {
    const {
      id,
      params: { projectId },
      body: { name, deadline },
    } = request;
    const { rows: projects } = await client.query(
      'SELECT * FROM projects WHERE id = $1 AND userid = $2',
      [projectId, id]
    );
    if (!projects.length) {
      return reply.status(403).send('Go away');
    }

    await client.query(
      'INSERT INTO tasks(name, deadline, projectid) VALUES ($1, $2, $3)',
      [name, deadline, projectId]
    );

    return reply.send(
      (
        await client.query('SELECT * FROM tasks WHERE projectid = $1', [
          projectId,
        ])
      ).rows
    );
  });

  server.patch('/projects/:projectId/tasks/:taskId', async (request, reply) => {
    const {
      id,
      params: { projectId, taskId },
    } = request;
    const { rows: projects } = await client.query(
      'SELECT * FROM projects WHERE id = $1 AND userid = $2',
      [projectId, id]
    );
    if (!projects.length) {
      return reply.status(403).send('Go away');
    }

    const {
      rows: [{ iscompleted }],
    } = await client.query(
      'SELECT * FROM tasks WHERE id = $1 AND projectid = $2',
      [taskId, projectId]
    );
    await client.query('UPDATE tasks SET iscompleted = $1 WHERE id = $2', [
      !iscompleted,
      taskId,
    ]);

    return reply.send(
      (
        await client.query('SELECT * FROM tasks WHERE projectid = $1', [
          projectId,
        ])
      ).rows
    );
  });

  next();
});

export default fastify;
