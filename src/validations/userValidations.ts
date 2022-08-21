import { check } from 'express-validator';

const save = [
  check('name').isLength({ min: 3 }).withMessage('O nome deve ter no mínimo 3 caracteres'),
  check('email').isEmail().withMessage('Não é um email válido'),
  check('password')
    .isStrongPassword({
      minLength: 8,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    })
    .withMessage('A senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos'),
  check('confirmPassword')
    .isStrongPassword({
      minLength: 8,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    })
    .withMessage('A confirmação de senha deve ter uma combinação de 8 caracteres com pelo menos 1 números, letras, sinais de pontuação e símbolos'),
];

export default { save };
