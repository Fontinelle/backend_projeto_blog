import { Router } from 'express';
import user from '../controllers/user';
import admin from '../middleware/admin';
import authenticate from '../middleware/authenticate';
import userValidations from '../validations/userValidations';
import validation from '../middleware/validation';

const router = Router();

router.post('/signin', user.signIn);
router.post('/signup', userValidations.save, validation, user.save);
router.post('/users', authenticate, admin, userValidations.save, validation, user.save);

export default router;
