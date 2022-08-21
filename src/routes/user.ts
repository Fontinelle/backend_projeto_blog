import { Router } from 'express';
import user from '../controllers/user';

const router = Router();

router.post('/signin', user.signIn);

export default router;
