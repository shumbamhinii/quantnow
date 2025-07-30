import axios from 'axios';
import dotenv from 'dotenv';
import { Request, Response } from 'express';

dotenv.config();

const PYTHON_NLP_URL = process.env.PYTHON_NLP_URL || 'http://localhost:8000';

export const parseText = async (req: Request, res: Response): Promise<void> => {
  const { text } = req.body;

  try {
    const response = await axios.post(`${PYTHON_NLP_URL}/nlp/parse`, { text });
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to parse text' });
  }
};
