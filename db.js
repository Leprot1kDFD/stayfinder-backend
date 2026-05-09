require('dotenv').config();

const { Pool } = require('pg');

console.log("DATABASE_URL exists:", !!process.env.DATABASE_URL);
console.log("DB_HOST exists:", process.env.DB_HOST || "no DB_HOST");

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.on('connect', () => {
    console.log('PostgreSQL connected');
});

pool.on('error', (err) => {
    console.error('PostgreSQL pool error:', err.message);
});

module.exports = pool;