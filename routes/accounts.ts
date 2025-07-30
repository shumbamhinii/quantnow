import express from 'express';
import { getAccounts, createAccount } from '../controllers/accountsController.js';

const router = express.Router();

router.get('/', getAccounts);
router.post('/', createAccount);

export default router;
