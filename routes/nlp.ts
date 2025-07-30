import express from 'express';
import { parseText } from '../controllers/nlpController.js';

const router = express.Router();

router.post('/parse', parseText);

export default router;
