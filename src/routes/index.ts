import { Router } from 'express';
import user from './user';

const router = Router();

router.get('/', (req, res) => res.send({ ok: true }));
router.use(user);

export default router;
