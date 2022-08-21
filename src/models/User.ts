import { InferCreationAttributes, Model, DataTypes } from 'sequelize';
import db from '../config/database';

interface IUser extends Model<InferCreationAttributes<IUser>> {
  id?: number;
  name: string;
  email: string;
  password: string;
  admin: boolean;
  deleted?: boolean;
}

const User = db.define<IUser>(
  'user',
  {
    id: { type: DataTypes.INTEGER, autoIncrement: true, allowNull: false, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    admin: { type: DataTypes.BOOLEAN, defaultValue: false },
    deleted: { type: DataTypes.BOOLEAN, defaultValue: false },
  },
  { timestamps: true },
);

export default User;
