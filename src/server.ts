import app from './app';
import db from './config/database';

const port = process.env.PORT || 3001;

(async () => {
  try {
    await db.authenticate();
    console.log('Connection has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
})();

const server = app.listen(port, () => {
  console.log(`Api running on port ${port}`);
});

process.on('SIGINT', () => {
  server.close();
  console.log('finished API');
});
