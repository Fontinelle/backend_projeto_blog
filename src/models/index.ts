import User from './User';

const models = [User];

models.forEach(async (model) => await model.sync());

export default models;
