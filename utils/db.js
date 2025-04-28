require("dotenv").config();

const { Pool } = require("pg");

const pool = new Pool({
  host: "localhost", // Ganti dengan host PostgreSQL Anda
  user: "postgres", // Ganti dengan username PostgreSQL Anda
  password: "12345678", // Ganti dengan password PostgreSQL Anda
  database: "userAuthentikasi", // Ganti dengan nama database PostgreSQL Anda
  port: 5432, // Port default PostgreSQL
});

module.exports = pool;
