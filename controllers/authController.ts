import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import prisma from '../prisma/prismaClient'; // Adjust the path as needed
import jwt from 'jsonwebtoken';
import dotenv from "dotenv";

dotenv.config();

const SECRET_KEY = process.env.SECRET_KEY || 'oASVUyg1cPzbKglgjMIetErJOEhA';

// Login controller
export const login = async (req: Request, res: Response): Promise<any> => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' }) as any;
  }


  // Find the user in the database
  const user = await prisma.users.findUnique({
    where: { username },
  });

  // Check if user exists and password is correct
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' }) as any;
  }

  // Generate JWT
  const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  return res.json({ token }) as any;
};

// Register controller
export const register = async (req: Request, res: Response): Promise<any> => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' }) as any;
  }
  if (!role) {
    return res.status(400).json({ message: 'Role is required' }) as any;
  }
  // Check if the user already exists
  const existingUser = await prisma.users.findUnique({
    where: { username },
  });

  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' }) as any;
  }

  // Hash the password and create the new user
  const hashedPassword = bcrypt.hashSync(password, 8);
  
  await prisma.users.create({
    data: {
      username,
      password: hashedPassword,
      role,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  return res.status(201).json({ message: 'User registered successfully' }) as any;
};