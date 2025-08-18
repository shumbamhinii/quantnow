import { Request, Response } from 'express';
import pool from '../db/index.js';

export const getTransactions = async (req: Request, res: Response): Promise<void> => {
  try {
    const result = await pool.query('SELECT * FROM transactions ORDER BY date DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
};

export const createManualTransaction = async (req: Request, res: Response): Promise<void> => {
  const { type, amount, description, date, category, account_id } = req.body;
  try {
    const query = `
      INSERT INTO transactions (type, amount, description, date, category, account_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `;
    const values = [type, amount, description, date, category, account_id || null];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create transaction' });
  }
};
