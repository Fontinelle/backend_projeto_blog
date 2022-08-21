import express, { Application } from 'express';
import cors from 'cors';
import helmet from 'helmet';

import router from './routes';

const app: Application = express();

app.use(cors());
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(router);

export default app;
