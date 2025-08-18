import { Request, Response } from 'express';
import pool from '../db/index.js';

export const getAccounts = async (req: Request, res: Response): Promise<void> => {
  try {
    const result = await pool.query('SELECT * FROM accounts ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch accounts' });
  }
};

export const createAccount = async (req: Request, res: Response): Promise<void> => {
  const { code, name, type, parent_account_id } = req.body;
  try {
    const query = `
      INSERT INTO accounts (code, name, type, parent_account_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
    const values = [code, name, type, parent_account_id || null];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create account' });
  }
};
