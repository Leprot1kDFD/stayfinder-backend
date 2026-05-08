require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.on('connect', () => {
    console.log('PostgreSQL connected');
});

pool.on('error', (err) => {
    console.error('PostgreSQL error:', err);
});

module.exports = pool;