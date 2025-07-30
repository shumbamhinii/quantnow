import express from 'express';
import { getTransactions, createManualTransaction } from '../controllers/transactionsController.js';

const router = express.Router();

router.get('/', getTransactions);
router.post('/manual', createManualTransaction);

export default router;
