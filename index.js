const express = require('express');
const mysql = require('mysql2');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { authenticate } = require('./middleware');
require('dotenv').config();

const server = express();
server.use(express.json());
server.use(cors());

const mysqlConfig = {
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASS,
  database: 'reactdb',
};

const adminRegistSchema = Joi.object({
  full_name: Joi.string().trim().required(),
  email: Joi.string().email().trim().lowercase().required(),
  password: Joi.string().required(),
  repeatPassword: Joi.string().required(),
});

const adminLoginSchema = Joi.object({
  email: Joi.string().email().trim().lowercase().required(),
  password: Joi.string().required(),
});

const clientRegistSchema = Joi.object({
  fullName: Joi.string().required(),
  email: Joi.string().email().required(),
  age: Joi.number().integer().required(),
});

const dbPool = mysql.createPool(mysqlConfig).promise();

server.get('/', authenticate, (req, res) => {
  res.status(200).send({ message: 'Authorized' });
});

server.post('/register', async (req, res) => {
  let payload = req.body;
  try {
    payload = await adminRegistSchema.validateAsync(payload);
  } catch (error) {
    return res.status(400).send({ error: 'All fields are required' });
  }

  try {
    const encryptedPassword = await bcrypt.hash(payload.password, 10);
    const [response] = await dbPool.execute(
      `
      INSERT INTO login (full_name, email, password)
      VALUES (?, ?, ?)
      `,
      [payload.full_name, payload.email, encryptedPassword],
    );
    const token = jwt.sign(
      {
        full_name: payload.full_name,
        email: payload.email,
        id: response.insertId,
      },
      process.env.JWT_SECRET,
    );
    return res.status(201).json({ token });
  } catch (error) {
    return res.status(500).end();
  }
});

server.post('/login', async (req, res) => {
  let payload = req.body;

  try {
    payload = await adminLoginSchema.validateAsync(payload);
  } catch (error) {
    return res.status(400).send({ error: 'All fields are required' });
  }

  try {
    const [data] = await dbPool.execute(
      `
      SELECT * FROM login
      WHERE email = ?`,
      [payload.email],
    );

    if (!data.length) {
      return res.status(400).send({ error: 'Email or password did not match' });
    }
    const isPasswordMatching = await bcrypt.compare(
      payload.password,
      data[0].password,
    );

    if (isPasswordMatching) {
      const token = jwt.sign(
        {
          email: data[0].email,
          id: data[0].id,
        },
        process.env.JWT_SECRET,
      );
      return res.status(200).send({ token });
    }

    return res.status(400).send({ error: 'Email or password did not match' });
  } catch (error) {
    return res.status(500).end();
  }
});

server.get('/clients', authenticate, async (req, res) => {
  try {
    const [clients] = await dbPool.execute('SELECT * FROM clients');
    return res.json(clients);
  } catch (error) {
    return res.status(500).end();
  }
});

server.post('/clients', authenticate, async (req, res) => {
  const { fullName, email, age } = req.body;
  try {
    await clientRegistSchema.validateAsync({ fullName, email, age });
  } catch (validationError) {
    return res.status(400).json({ error: 'Invalid input data' });
  }

  try {
    const [client] = await dbPool.execute(
      `
      INSERT INTO clients (full_name, email, age)
      VALUES (?, ?, ?)
      `,
      [fullName, email, age],
    );
    const insertId = client.insertId;
    const [rows] = await dbPool.execute(
      `
        SELECT * FROM clients WHERE id = ?
         `,
      [insertId],
    );
    const newClient = rows[0];
    return res.status(201).send(newClient);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

server.delete('/clients/:id', authenticate, async (req, res) => {
  const clientId = req.params.id;

  try {
    const [existingClient] = await dbPool.execute(
      'SELECT * FROM clients WHERE id = ?',
      [clientId],
    );
    if (!existingClient.length) {
      return res.status(404).json({ error: 'Client not found' });
    }
    await dbPool.execute(
      'DELETE FROM clients WHERE id = ?',
      [clientId],
    );
    return res.status(200).json({ message: 'Client deleted successfully' });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

server.listen(process.env.PORT, () => console.log(`Server is running on port ${process.env.PORT}`));
