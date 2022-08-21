import { Sequelize, Dialect } from 'sequelize';
import 'dotenv/config';

const db_database = process.env.NODE_ENV === 'test' ? 'test' : (process.env.DB_DATABASE as string);

const database = db_database;
const username = process.env.DB_USERNAME as string;
const password = process.env.DB_PASSWORD as string;
const host = process.env.DB_HOST as string;
const dialect = process.env.DB_DIALECT as Dialect;

const db = new Sequelize(database, username, password, { host, dialect });

export default db;
