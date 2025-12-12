import { MongoClient } from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this';

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST,PUT,DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Todos os campos são obrigatórios' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        error: 'Senha deve ter no mínimo 6 caracteres' 
      });
    }

    const client = await MongoClient.connect(uri);
    const db = client.db();

    const existingUser = await db.collection('users').findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      await client.close();
      return res.status(400).json({ 
        success: false, 
        error: 'Username ou email já está em uso' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.collection('users').insertOne({
      username,
      email,
      password: hashedPassword,
      discordId: null,
      createdAt: new Date()
    });

    const token = jwt.sign({ 
      userId: result.insertedId.toString(),
      username,
      email
    }, JWT_SECRET, { expiresIn: '30d' });

    await client.close();

    res.status(201).json({
      success: true,
      token,
      user: {
        id: result.insertedId,
        username,
        email
      }
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ success: false, error: 'Erro ao criar usuário' });
  }
}
