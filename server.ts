import dotenv from 'dotenv';
dotenv.config();


import cors from 'cors';
import { Pool, PoolClient } from 'pg';
import multer from 'multer';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { createClient } from '@supabase/supabase-js';
import axios from 'axios';
import express, { Request, Response, NextFunction } from 'express';
import puppeteer from 'puppeteer';
import path from 'path';
const app = express();
const PORT = 3000;
const PDFDocument = require('pdfkit');

app.use(cors({
  origin: '*',
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const supabaseUrl = "https://phoaahdutroiujxiehze.supabase.co";
const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBob2FhaGR1dHJvaXVqeGllaHplIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NTE3MjU1MSwiZXhwIjoyMDcwNzQ4NTUxfQ.XbnwOjhIil3O9NEmfhXSiORC8jdEOYx4fxQR8AtHKD0";
const supabase = createClient(supabaseUrl!, supabaseKey!);

const pool = new Pool({
  connectionString:
    "postgresql://qbeta_db:E5sNOxattCokbXt7aWqDSIFi2YHznCYl@dpg-d2ndml75r7bs73fes2d0-a.oregon-postgres.render.com/qbeta_db_jg0t",
  max: 5, // keep small, 3–5 is plenty
  idleTimeoutMillis: 30000,
  //connectionTimeoutMillis: 5000,
  ssl: { rejectUnauthorized: false },
});

pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    if (client) {
        client.query('SELECT NOW()', (queryErr, result) => {
            release();
            if (queryErr) {
                return console.error('Error executing query', queryErr.stack);
            }
            console.log('Connected to PostgreSQL database:', result.rows[0].now);
        });
    } else {
        release();
        console.error('Client is undefined after successful pool.connect');
    }
});

// Extend the Request interface to include the user property

// Extend the Request type to include the user property
// This declaration is crucial for TypeScript to understand the JWT payload
// attached to the request after authentication.
// Extend the Request type to include the user property
// This declaration is crucial for TypeScript to understand the JWT payload
// attached to the request after authentication.
// Extend the Request type to include the user property.
// We are now correctly using 'user_id' as the unique identifier from the database.
declare global {
  namespace Express {
    interface Request {
      user?: {
        user_id: string;
        parent_user_id: string; // <--- add this line
      };
    }
  }
}


// AUTHENTICATION MIDDLEWARE (on your backend server)
const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
// console.log('--- Inside authMiddleware ---');
//console.log('Request Headers:', req.headers); // Log all headers
  const authHeader = req.headers.authorization;
//console.log('Authorization Header:', authHeader); // Log the Authorization header directly

  const token = authHeader?.split(' ')[1];
  //console.log('Extracted Token:', token ? token.substring(0, 10) + '...' : 'No token extracted'); // Log first 10 chars of token for brevity

  const secret = process.env.JWT_SECRET;
  console.log('JWT_SECRET (first 5 chars):', secret ? secret.substring(0, 5) + '...' : 'NOT DEFINED'); // Log part of secret

  if (!secret) {
    //console.error('❌ JWT_SECRET not defined in .env');
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  if (!token) {
    console.warn('Authentication Failed: No token provided in header.');
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, secret);
    console.log('Token Decoded Successfully:', decoded);
    req.user = decoded as { user_id: string; parent_user_id: string };

    next();
  } catch (err) {
    console.error('Authentication Failed: Invalid token', err);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Configure Nodemailer transporter with OAuth2
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_SERVICE_HOST,
    port: Number(process.env.EMAIL_SERVICE_PORT),
    secure: Number(process.env.EMAIL_SERVICE_PORT) === 465, // true for 465 (SSL/TLS)
    auth: {
        user: process.env.EMAIL_SERVICE_USER,
        pass: process.env.EMAIL_SERVICE_PASS, // <--- Use the App Password here
    },
});

// Optional: Verify transporter connection (good for debugging)
transporter.verify(function (error, success) {
    if (error) {
        console.error("Nodemailer transporter verification failed:", error);
    } else {
        console.log("Nodemailer transporter is ready to send messages.");
    }
});

// --- Generic Email Sending Function ---
interface EmailOptions {
  to: string;
  subject: string;
  text?: string;
  html?: string;
  attachments?: nodemailer.SendMailOptions['attachments'];
}

async function sendEmail(options: EmailOptions) {
  try {
    const info = await transporter.sendMail({
      from: `"${process.env.APP_NAME || 'Your Company'}" <${process.env.EMAIL_SERVICE_USER}>`,
      to: options.to,
      subject: options.subject,
      text: options.text,
      html: options.html,
      attachments: options.attachments,
    });
    console.log('Email sent successfully! Message ID: %s', info.messageId);
    return true; // Indicate success
  } catch (error) {
    console.error('Failed to send email:', error);
    if (error instanceof Error) {
        console.error('Error name:', error.name);
        console.error('Error message:', error.message);
        // @ts-ignore // Nodemailer specific properties
        if (error.responseCode) console.error('Response Code:', error.responseCode);
        // @ts-ignore
        if (error.response) console.error('Response:', error.response);
    }
    return false; // Indicate failure
  }
}





// File upload setup
const upload = multer({ storage: multer.memoryStorage() });

// Corrected code for your upload route

// Corrected upload-document endpoint to save file type
app.post('/upload-document', authMiddleware, upload.single('document'), async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const user_id = req.user!.user_id;
  const bucketName = 'user-documents';
  const uniqueFileName = `${user_id}/${Date.now()}_${req.file.originalname}`;
  
  try {
    const { data, error: uploadError } = await supabase.storage
      .from(bucketName)
      .upload(uniqueFileName, req.file.buffer, {
        cacheControl: '3600',
        upsert: true,
        contentType: req.file.mimetype,
        duplex: 'half'
      });

    if (uploadError) {
      console.error('Supabase upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload document.' });
    }

    // Insert the document record, including the file type
    await pool.query(
      `INSERT INTO user_documents (user_id, original_name, file_path, type) VALUES ($1, $2, $3, $4)
       ON CONFLICT (file_path) DO NOTHING;`,
      [user_id, req.file.originalname, data!.path, req.file.mimetype]
    );

    res.status(201).json({ message: 'Document uploaded successfully!', filePath: data!.path });
  } catch (error) {
    console.error('Unexpected error:', error);
    if (uniqueFileName) {
      await supabase.storage.from(bucketName).remove([uniqueFileName]);
    }
    res.status(500).json({ error: 'An unexpected error occurred while processing the document.' });
  }
});

// Update GET /documents endpoint to return the type
app.get('/documents', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.user_id;

    try {
      const { rows } = await pool.query(
        // Include 'type' in the SELECT statement
        `SELECT id, original_name, file_path, type, upload_date FROM user_documents WHERE user_id = $1 ORDER BY upload_date DESC`,
        [user_id]
      );

      res.status(200).json(rows);
    } catch (error) {
      console.error('Error fetching documents:', error);
      res.status(500).json({ error: 'Failed to fetch documents.' });
    }
});
// Corrected DELETE /documents/:id endpoint
// Corrected DELETE /documents/:id endpoint
app.delete('/documents/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const user_id = req.user!.user_id;
  const bucketName = 'user-documents'; // Your bucket name

  try {
    // Start a transaction to ensure both DB and storage operations succeed or fail together
    await pool.query('BEGIN');

    // 1. Get the file path first to delete it from storage
    const { rows } = await pool.query(
      `SELECT file_path FROM user_documents WHERE id = $1 AND user_id = $2`,
      [id, user_id]
    );

    if (rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Document not found or unauthorized.' });
    }

    const filePath = rows[0].file_path;

    // 2. Delete the document record from the database
    const { rowCount } = await pool.query(
      `DELETE FROM user_documents WHERE id = $1 AND user_id = $2`,
      [id, user_id]
    );

    if (rowCount === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Document not found or unauthorized.' });
    }

    // 3. Delete the file from Supabase Storage
    const { error: storageError } = await supabase.storage.from(bucketName).remove([filePath]);
    if (storageError) {
      // If storage deletion fails, roll back the DB transaction
      await pool.query('ROLLBACK');
      console.error('Supabase storage deletion error:', storageError);
      return res.status(500).json({ error: 'Failed to delete file from storage. Database was not affected.' });
    }

    // Commit the transaction
    await pool.query('COMMIT');
    res.status(204).send(); // 204 No Content for successful deletion
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error deleting document:', error);
    res.status(500).json({ error: 'Failed to delete document. Operation rolled back.' });
  }
});

// The correct GET /documents/:id/download endpoint (already correct)
// The correct GET /documents/:id/download endpoint (already correct)
app.get('/documents/:id/download', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const user_id = req.user!.user_id;
  const bucketName = 'user-documents';

  // REMOVED: supabase.auth.setAuth(token); // Not needed with service_role key

  try {
    const { rows } = await pool.query(
      `SELECT file_path, original_name FROM user_documents WHERE id = $1 AND user_id = $2`,
      [id, user_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Document not found or unauthorized.' });
    }

    const { file_path, original_name } = rows[0];

    const { data, error } = await supabase.storage
      .from(bucketName)
      .createSignedUrl(file_path, 3600); // URL valid for 1 hour

    if (error) {
      console.error('Error creating signed URL:', error);
      return res.status(500).json({ error: 'Failed to generate download link.' });
    }

    res.redirect(data.signedUrl);
  } catch (error) {
    console.error('Error during document download:', error);
    res.status(500).json({ error: 'Failed to process download request.' });
  }
});
// Add this endpoint to your server.ts file
// The correct GET /documents endpoint (already correct)


// Add this new endpoint to your server.ts file
app.patch('/documents/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { original_name, type } = req.body;
  const user_id = req.user!.user_id;

  if (!original_name || !type) {
    return res.status(400).json({ error: 'Original name and type are required.' });
  }

  try {
    const { rowCount } = await pool.query(
      `UPDATE user_documents
       SET original_name = $1, type = $2
       WHERE id = $3 AND user_id = $4`,
      [original_name, type, id, user_id]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: 'Document not found or unauthorized.' });
    }

    res.status(200).json({ message: 'Document updated successfully.' });
  } catch (error) {
    console.error('Error updating document:', error);
    res.status(500).json({ error: 'Failed to update document.' });
  }
});

interface SupplierDB { // Represents how data comes from the DB (public.suppliers table)
    id: number;
    name: string;
    email: string | null;
    phone: string | null;
    address: string | null;
    vat_number: string | null; // Matches DB column name
    total_purchased: number; // Matches DB column name, NOT NULL with default 0.00
    created_at?: Date;
    updated_at?: Date;
}

// Utility function to map DB schema to frontend interface
const mapSupplierToFrontend = (supplier: SupplierDB) => ({
    id: supplier.id.toString(), // Convert number ID to string for React
    name: supplier.name,
    email: supplier.email || '', // Ensure it's a string, not null
    phone: supplier.phone || '',
    address: supplier.address || '',
    vatNumber: supplier.vat_number || '', // Map snake_case to camelCase
    totalPurchased: supplier.total_purchased, // Map snake_case to camelCase
});
// Add these interfaces and the mapping function near your SupplierDB and mapSupplierToFrontend

// Interface matching the public.products_services table structure
interface ProductDB {
    id: number;
    name: string;
    description: string | null;
    unit_price: number; // From DB
    cost_price: number | null;
    sku: string | null;
    is_service: boolean;
    stock_quantity: number; // From DB
    created_at: Date;
    updated_at: Date;
    tax_rate_id: number | null; // Foreign key
    category: string | null;
    unit: string | null;
    // Potentially include the tax rate itself from the joined table
    tax_rate_value?: number; // The actual rate (e.g., 0.15) from tax_rates table
}
interface UserProfile {
  company?: string | null;
  email?: string | null;
  address?: string | null;
  city?: string | null;
  province?: string | null;
  postal_code?: string | null;
  country?: string | null;
  phone?: string | null;
  vat_number?: string | null;
  reg_number?: string | null;
  contact_person?: string | null;
}

// Interface for what the frontend expects (camelCase)
interface ProductFrontend {
    id: string; // React often prefers string IDs
    name: string;
    description: string; // Frontend might expect string, even if DB has null
    price: number;
    costPrice?: number; // Optional for frontend if not always displayed
    sku?: string; // Optional for frontend
    isService: boolean; // camelCase
    stock: number; // camelCase
    vatRate: number; // Actual percentage (e.g., 0.15)
    category: string;
    unit: string;
}

// Interface for what the frontend sends when creating/updating a product
// Note: id and totalPurchased (if any, though not for products) are excluded.
// vatRate is the *value*, not the ID.
interface CreateUpdateProductBody {
    name: string;
    description?: string;
    price: number; // Corresponds to unit_price
    costPrice?: number;
    sku?: string;
    isService?: boolean;
    stock?: number; // Corresponds to stock_quantity
    vatRate?: number; // The actual tax rate value (e.g., 0.15)
    category?: string;
    unit?: string;
}

// Helper function to map database product object to frontend product object
const mapProductToFrontend = (product: ProductDB): ProductFrontend => ({
    id: product.id.toString(),
    name: product.name,
    description: product.description || '', // Ensure it's a string for frontend
    price: Number(product.unit_price), // Convert numeric to number
    costPrice: product.cost_price ? Number(product.cost_price) : undefined,
    sku: product.sku || undefined,
    isService: product.is_service,
    stock: Number(product.stock_quantity), // Convert numeric to number
    vatRate: product.tax_rate_value !== undefined && product.tax_rate_value !== null ? Number(product.tax_rate_value) : 0, // Default to 0 if null/undefined
    category: product.category || '',
    unit: product.unit || '',
});
interface CustomerDB {
    id: number;
    name: string;
    contact_person: string | null;
    email: string | null;
    phone: string | null;
    address: string | null;
    tax_id: string | null; // Matches DB column name
    total_invoiced: number; // Matches DB column name
    created_at?: Date;
    updated_at?: Date;
}

// Interface for what the frontend expects (camelCase)
interface CustomerFrontend {
    id: string; // React often prefers string IDs
    name: string;
    email: string;
    phone: string;
    address: string;
    vatNumber: string; // camelCase, maps to tax_id
    totalInvoiced: number; // camelCase, maps to total_invoiced
}

// Interface for what the frontend sends when creating/updating a customer
// contactPerson and vatNumber are camelCase for frontend consistency
interface CreateUpdateCustomerBody {
    name: string;
    contactPerson?: string; // Maps to contact_person
    email?: string;
    phone?: string;
    address?: string;
    vatNumber?: string;
    customFields?: string; // Maps to tax_id
}

// Helper function to map database customer object to frontend customer object
const mapCustomerToFrontend = (customer: CustomerDB): CustomerFrontend => ({
    id: customer.id.toString(), // Convert number ID to string
    name: customer.name,
    email: customer.email || '',
    phone: customer.phone || '',
    address: customer.address || '',
    vatNumber: customer.tax_id || '', // Map tax_id to vatNumber
    totalInvoiced: Number(customer.total_invoiced), // Ensure it's a number
});
 export interface ProductService {
  id: string;
  name: string;
  description: string;
  price: number; // This is 'price' (number) from ProductFrontend, not 'unit_price' (string) from DB
  costPrice?: number;
  sku?: string;
  isService: boolean;
  stock: number;
  vatRate: number; // Decimal (e.g., 0.15)
  category: string;
  unit: string;
}



// Assuming 'app', 'pool', 'authMiddleware', 'bcrypt', 'uuidv4', 'Request', 'Response' are defined elsewhere

// Assuming 'app', 'pool', 'authMiddleware', 'bcrypt', 'uuidv4', 'Request', 'Response' are defined elsewhere

// In your backend (e.g., server.ts or routes/auth.ts)

// --- Add these imports at the top if not already present ---
// import bcrypt from 'bcryptjs';
// import { v4 as uuidv4 } from 'uuid';
// import jwt from 'jsonwebtoken';
// --- End imports ---

// --- Registration Endpoint (Updated for Extended Frontend Form AND Default Accounts) ---
// --- Registration Endpoint (Updated for Extended Frontend Form AND Default Accounts) ---
app.post('/register', async (req: Request, res: Response) => {
  // --- Destructure ALL fields expected from the enhanced frontend form ---
  const {
    name, // Combined First Name + Last Name (Primary name field for users table)
    email,
    password,
    // --- Extended Registration Fields from Request Body ---
    surname, // Received but combined into 'name' field
    company, // Maps directly to 'company' column
    position, // Maps directly to 'position' column
    phone, // Maps directly to 'phone' column (optional)
    address, // Maps directly to 'address' column
    city, // Maps directly to 'city' column
    province, // Maps directly to 'province' column
    country, // Maps directly to 'country' column
    postal_code, // Maps directly to 'postal_code' column
    registrationType, // Received but NOT stored (unless you add a column)
    companySize, // Received but NOT stored (unless you add a column)
    gender, // Received but NOT stored (unless you add a column)
    // --- End Extended Registration Fields ---
  } = req.body;

  console.log(`[AUTH] Registration attempt received for email: ${email}`);

  // --- Enhanced Server-Side Validation ---
  // Check for presence of core required fields for registration and profile
  if (!name || !email || !password || !company || !position ||
      !address || !city || !province || !country || !postal_code) {
    console.warn(`[AUTH] Registration failed for ${email}: Missing required fields.`);
    return res.status(400).json({
      error: 'Registration failed. Please provide all required information (marked with *).',
      // Optionally, you could list the specific missing fields for better UX
      // missingFields: [...] 
    });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
      console.warn(`[AUTH] Registration failed for ${email}: Invalid email format.`);
      return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  // Validate password strength (basic example: min length)
  if (password.length < 6) {
      console.warn(`[AUTH] Registration failed for ${email}: Password too short.`);
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }
  // --- End Enhanced Server-Side Validation ---

  try {
    // --- Check for Existing User ---
    const existingUserResult = await pool.query(
      'SELECT id FROM public.users WHERE email = $1',
      [email]
    );
    if (existingUserResult.rows.length > 0) {
      console.warn(`[AUTH] Registration failed for ${email}: Email already exists.`);
      return res.status(409).json({ error: 'An account with this email address already exists.' });
    }
    // --- End Check for Existing User ---

    // --- Hash Password ---
    const saltRounds = 10; // Standard value for bcrypt
    const password_hash = await bcrypt.hash(password, saltRounds);
    console.log(`[AUTH] Password hashed successfully for ${email}.`);
    // --- End Hash Password ---

    // --- Generate Unique User ID ---
    const newUserId = uuidv4(); // Generate a unique UUID for the new user
    console.log(`[AUTH] Generated new user ID: ${newUserId} for ${email}.`);
    // --- End Generate Unique User ID ---

    // --- BEGIN DATABASE TRANSACTION ---
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      console.log(`[AUTH] Database transaction started for ${email}.`);

      // --- Step 1: Insert New User into Database (WITH Extended Profile Fields) ---
      // Note: 'registrationType', 'companySize', 'gender' are received but not inserted here
      // unless you add corresponding columns to the `public.users` table.
      const insertUserResult = await client.query(
        `INSERT INTO public.users (
           user_id, -- UUID string
           name, -- Combined first & last name from frontend
           email,
           password_hash,
           company, -- From frontend
           position, -- From frontend
           phone, -- From frontend (optional)
           address, -- From frontend
           city, -- From frontend
           province, -- From frontend
           country, -- From frontend
           postal_code, -- From frontend
           role -- Assign initial role (e.g., 'admin')
           -- Add new columns here if you create them, e.g.,
           -- registration_type, company_size, gender
         ) VALUES (
           $1, $2, $3, $4,
           $5, $6, $7, $8, $9, $10, $11, $12,
           $13
           -- Add corresponding values here if you add new columns, e.g.,
           -- $14, $15, $16
         ) RETURNING id, user_id, name, email, role`,
         // Values array matching placeholders ($1, $2, ...)
       [
         newUserId, name, email, password_hash,
         company, position, phone || null, address, city, province, country, postal_code,
         'admin' // Assign 'admin' role to the registering user
         // Add values for new columns here if you add them, e.g.,
         // registrationType || null, companySize || null, gender || null
       ]
      );
      const newUser = insertUserResult.rows[0]; // Get the inserted user data
      console.log(`[AUTH] New user inserted successfully: ID ${newUser.id}, user_id ${newUser.user_id}`);
      // --- End Step 1: Insert New User ---

      // --- Step 2: Insert Default Role into `user_roles` table ---
      // This maintains consistency with the original logic if you use user_roles elsewhere.
      await client.query(`
        INSERT INTO public.user_roles (user_id, role)
        VALUES ($1, $2)
      `, [newUserId, 'admin']); // Use the same role assigned in Step 1
      console.log(`[AUTH] Default 'admin' role inserted for user_id: ${newUserId}.`);
      // --- End Step 2: Insert Default Role ---

      // --- Step 3: Insert Default Accounts based on ImportScreen.tsx ---
      // These accounts provide a base set for transaction categorization
      // and align with the logic in the frontend's suggestion functions.
   const defaultAccounts: [string, 'Asset'|'Liability'|'Equity'|'Income'|'Expense', string, string][] = [
  // ── ASSETS (1000–1999)
  ['Bank Account',                     'Asset',    'Bank',                            '1000'],
  ['Cash',                             'Asset',    'Cash',                            '1100'],
  ['Accounts Receivable',              'Asset',    'Accounts Receivable',             '1200'], // FIXED: was Income
  ['Inventory',                        'Asset',    'Inventory',                       '1300'],
  ['Prepaid Expenses',                 'Asset',    'Prepaid Expenses',                '1400'],
  ['Property, Plant & Equipment',      'Asset',    'Fixed Assets',                    '1500'],
  // (Optional but recommended – see note on contra accounts below)
  ['Accumulated Depreciation',         'Asset',    'Contra Asset (PPE offset)',       '1550'],

  // VAT (South Africa typical handling)
  ['VAT Input (Receivable)',           'Asset',    'VAT',                             '1600'],

  // ── LIABILITIES (2000–2999)
  ['Accounts Payable',                 'Liability','Accounts Payable',                '2100'],
  ['VAT Output (Payable)',             'Liability','VAT',                             '2200'],
  ['VAT Control / Net Payable',        'Liability','VAT',                             '2210'],
  ['Accrued Expenses',                 'Liability','Accruals',                        '2300'],
  ['Unearned Revenue (Deferred)',      'Liability','Deferred Income',                 '2400'],
  ['Payroll Liabilities - PAYE',       'Liability','Statutory Payroll',               '2420'],
  ['Payroll Liabilities - UIF',        'Liability','Statutory Payroll',               '2430'],
  ['Payroll Liabilities - SDL',        'Liability','Statutory Payroll',               '2440'],
  ['Credit Facility Payable',          'Liability','Credit Facility',                 '2500'],
  ['Car Loans',                        'Liability','Vehicle Finance',                 '2600'],
  ['Long-term Loan Payable',           'Liability','Loans',                           '2700'],

  // ── EQUITY (3000–3999)
  ['Owner’s Capital',                  'Equity',   'Equity',                          '3000'],
  ['Retained Earnings',                'Equity',   'Equity',                          '3100'],
  ['Owner’s Drawings',                 'Equity',   'Contra Equity',                   '3200'],
  ['Opening Balance Equity',           'Equity',   'System',                          '3999'],

  // ── INCOME (4000–4999)
  ['Sales Revenue',                    'Income',   'Sales Revenue',                    '4000'],
  ['Sales Returns & Allowances',       'Income',   'Contra Revenue',                   '4050'],
  ['Other Income',                     'Income',   'Other Income',                     '4900'],
  ['Interest Income',                  'Income',   'Interest Income',                   '4100'],

  // ── COST OF SALES (5000–5999)
  ['Cost of Goods Sold',               'Expense',  'Cost of Goods Sold',               '5000'],
  ['Freight & Import Duties (COGS)',   'Expense',  'Cost of Goods Sold',               '5100'],

  // ── OPERATING EXPENSES (6000–7999)
  ['Salaries and Wages Expense',       'Expense',  'Salaries and Wages',               '6100'],
  ['Bank Charges & Fees',              'Expense',  'Bank Charges & Fees',              '6200'],
  ['Rent Expense',                     'Expense',  'Rent',                             '6300'],
  ['Repairs & Maintenance Expense',    'Expense',  'Repairs & Maintenance',           '6400'],
  ['Fuel Expense',                     'Expense',  'Fuel',                             '6500'],
  ['Utilities Expense',                'Expense',  'Utilities',                        '6600'],
  ['Insurance Expense',                'Expense',  'Insurance',                        '6700'],
  ['Loan Interest Expense',            'Expense',  'Loan Interest',                    '6800'],
  ['Communication Expense',            'Expense',  'Computer, Internet & Telephone',   '6900'],
  ['Website Hosting Fees',             'Expense',  'Website Hosting Fees',             '6950'],
  ['Accounting Fees Expense',          'Expense',  'Accounting Fees',                  '7000'],
  ['Depreciation Expense',             'Expense',  'Depreciation Expense',             '7770'],
  ['Bad Debts Expense',                'Expense',  'Credit Losses',                    '7800'],
  ['Miscellaneous Expense',            'Expense',  'Other Expenses',                   '7900'],
];

      for (const account of defaultAccounts) {
        await client.query(
          `INSERT INTO public.accounts (name, type, category, code, user_id)
           VALUES ($1, $2, $3, $4, $5)`,
          [account[0], account[1], account[2], account[3], newUserId]
        );
      }
      console.log(`[AUTH] ${defaultAccounts.length} default accounts created for user_id: ${newUserId}.`);
      // --- End Step 3: Insert Default Accounts ---

      // --- COMMIT DATABASE TRANSACTION ---
      await client.query('COMMIT');
      console.log(`[AUTH] Database transaction committed successfully for ${email}.`);
      // --- End COMMIT DATABASE TRANSACTION ---

      // --- Generate JWT Token ---
      // Ensure JWT_SECRET is defined in your environment variables (.env file)
      const JWT_SECRET = process.env.JWT_SECRET;
      if (!JWT_SECRET) {
          console.error("[AUTH] JWT_SECRET is not defined in environment variables.");
      }
      let token = null;
      if (JWT_SECRET) {
          token = jwt.sign(
            { user_id: newUser.user_id, email: newUser.email }, // Payload
            JWT_SECRET, // Secret key
            { expiresIn: '24h' } // Options
          );
          console.log(`[AUTH] JWT token generated for user_id: ${newUser.user_id}`);
      }
      // --- End Generate JWT Token ---

      // --- Respond with Success (Including Token) ---
      console.log(`[AUTH] User registered successfully: ${newUser.name} (${newUser.email})`);
      res.status(201).json({
        message: '🎉 Registration successful! Welcome to QxAnalytix. Default accounts created.',
        user: {
          user_id: newUser.user_id,
          name: newUser.name,
          email: newUser.email,
        },
        // Include the token only if it was successfully generated
        ...(token && { token: token })
      });
      // --- End Respond with Success ---

    } catch (transactionErr: any) {
      // --- HANDLE TRANSACTION ERRORS ---
      await client.query('ROLLBACK');
      console.error(`[AUTH] Database transaction rolled back for ${email} due to:`, transactionErr);
      throw transactionErr; // Re-throw to be caught by the outer catch block
      // --- END HANDLE TRANSACTION ERRORS ---
    } finally {
      // --- ALWAYS RELEASE CLIENT ---
      client.release();
      console.log(`[AUTH] Database client released for ${email}.`);
      // --- END ALWAYS RELEASE CLIENT ---
    }
    // --- END DATABASE TRANSACTION BLOCK ---
  } catch (err: any) {
    // --- Handle Outer Errors (including transaction errors) ---
    console.error('[AUTH] Registration error:', err);
    // Differentiate between database errors and others if needed
    // Example: Unique violation on email (though checked above, race condition possible)
    if (err.code === '23505') { // Unique violation
        console.error(`[AUTH] Registration failed for ${email}: Conflict (e.g., duplicate email).`);
        return res.status(409).json({ error: 'Registration failed due to a conflict. Please try again.' });
    }
    // Generic server error response
    res.status(500).json({
      error: '😢 Registration failed due to a server error. Please try again later.',
    });
    // --- End Handle Outer Errors ---
  }
});
// --- End Registration Endpoint ---

app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    console.log('🔐 Login attempt for:', email);

    const result = await pool.query(`
      SELECT 
        u.id,
        u.name,
        u.email,
        u.user_id,
        u.password_hash,
        u.parent_user_id,
        u.role AS fallback_role,  -- 👈 we use this only if user_roles is empty
        COALESCE(json_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '[]') AS roles
      FROM public.users u
      LEFT JOIN public.user_roles ur ON u.user_id = ur.user_id
      LEFT JOIN public.roles r ON ur.role = r.name
      WHERE u.email = $1
      GROUP BY u.id, u.name, u.email, u.user_id, u.password_hash, u.parent_user_id, u.role
    `, [email]);

    const user = result.rows[0];

    if (!user) {
      console.warn('❌ No user found for email:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const hash = typeof user?.password_hash === 'string'
      ? user.password_hash
      : user?.password_hash?.toString();

    const passwordMatch = await bcrypt.compare(password, hash);
    if (!passwordMatch) {
      console.warn('❌ Password mismatch for:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      console.error('❌ JWT_SECRET not defined in .env');
      return res.status(500).json({ error: 'Server misconfiguration' });
    }

    // ✅ Resolve final roles (from user_roles or fallback to users.role)
    const resolvedRoles = (user.roles && user.roles.length > 0)
      ? user.roles
      : (user.fallback_role ? [user.fallback_role] : []);

    const token = jwt.sign(
      {
        user_id: user.user_id,
        parent_user_id: user.parent_user_id || user.user_id,
      },
      secret
    );

    const responseUser = {
      user_id: user.user_id,
      parent_user_id: user.parent_user_id,
      name: user.name,
      email: user.email,
      roles: resolvedRoles
    };

    console.log('📤 Sending login response:', responseUser);

    res.json({
      token,
      user: responseUser
    });

  } catch (error) {
    console.error('💥 Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});


// Define the interface for PDF data again for clarity
interface QuotationDetailsForPdf {
    quotation_number: string;
    customer_name: string;
    customer_email?: string | null;
    customer_address?: string | null;
    quotation_date: string;
    expiry_date?: string;
    total_amount: number;
    currency: string;
    notes?: string | null;
    line_items: Array<{
        product_service_name?: string | null;
        description: string;
        quantity: number;
        unit_price: number;
        line_total: number;
        tax_rate: number;
    }>;
    companyName: string;
    companyAddress?: string | null;
    companyCity?: string | null; // <-- ADDED THIS
    companyProvince?: string | null; // <-- ADDED THIS
    companyPostalCode?: string | null; // <-- ADDED THIS
    companyCountry?: string | null; // <-- ADDED THIS
    companyVat?: string | null;
    companyReg?: string | null;
    companyPhone?: string | null;
    companyEmail?: string | null;
    companyLogoUrl?: string | null;
}



// Generic PDF generation endpoint for invoices and statements






async function generateQuotationPdf(quotationData: QuotationDetailsForPdf): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
        const doc = new PDFDocument({ margin: 50 });
        const buffers: Buffer[] = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        doc.on('error', reject);

        // --- Header Section ---
        let companyLogoBuffer: Buffer | null = null;
        let logoWidth = 120;
        const logoX = doc.page.width - doc.page.margins.right - logoWidth;

        if (quotationData.companyLogoUrl) {
            try {
                const logoResponse = await axios.get(quotationData.companyLogoUrl, { responseType: 'arraybuffer' });
                companyLogoBuffer = Buffer.from(logoResponse.data, 'binary');
                doc.image(companyLogoBuffer, logoX, 50, { width: logoWidth });
            } catch (error) {
                console.error('Failed to fetch company logo for PDF:', error);
                // Continue generating PDF without the logo if fetch fails
            }
        }
        
        // Company details - placed on the top-left side
        const companyDetailsY = 50;
        doc.fontSize(14).font('Helvetica-Bold').text(quotationData.companyName, 50, companyDetailsY);
        doc.moveDown(0.5);

        if (quotationData.companyAddress) {
            doc.fontSize(10).font('Helvetica').text(quotationData.companyAddress);
        }
        if (quotationData.companyCity || quotationData.companyProvince || quotationData.companyPostalCode || quotationData.companyCountry) {
            const addressLine2 = [quotationData.companyCity, quotationData.companyProvince, quotationData.companyPostalCode, quotationData.companyCountry]
                .filter(Boolean)
                .join(', ');
            doc.text(addressLine2);
        }
        if (quotationData.companyPhone) {
            doc.text(`Phone: ${quotationData.companyPhone}`);
        }
        if (quotationData.companyEmail) {
            doc.text(`Email: ${quotationData.companyEmail}`);
        }
        if (quotationData.companyVat) {
            doc.text(`VAT No: ${quotationData.companyVat}`);
        }
        if (quotationData.companyReg) {
            doc.text(`Reg No: ${quotationData.companyReg}`);
        }

        doc.moveDown(2);

        // --- Quotation Details and Title ---
        doc.fontSize(30).font('Helvetica-Bold').text(`QUOTATION`, { align: 'center' });
        doc.moveDown(1);
        doc.fontSize(12).font('Helvetica').text(`Quotation #: ${quotationData.quotation_number}`, { align: 'center' });
        doc.fontSize(10).text(`Quotation Date: ${new Date(quotationData.quotation_date).toLocaleDateString('en-ZA')}`, { align: 'center' });
        if (quotationData.expiry_date) {
            doc.fontSize(10).text(`Expiry Date: ${new Date(quotationData.expiry_date).toLocaleDateString('en-ZA')}`, { align: 'center' });
        }
        doc.moveDown(2);

        // --- Customer Details ---
        doc.fontSize(12).font('Helvetica-Bold').text('Quotation For:');
        doc.fontSize(12).font('Helvetica').text(quotationData.customer_name);
        if (quotationData.customer_address) {
            doc.fontSize(10).text(quotationData.customer_address);
        }
        if (quotationData.customer_email) {
            doc.fontSize(10).text(quotationData.customer_email);
        }
        doc.moveDown(2);
        
        // Line Items table - Matching Invoice Column Definitions
        const tableTop = doc.y;
        const col1X = 50;  // Description
        const col2X = 250; // Qty
        const col3X = 300; // Unit Price
        const col4X = 400; // Tax Rate
        const col5X = 470; // Line Total

        doc.fontSize(10).font('Helvetica-Bold')
            .text('Description', col1X, tableTop)
            .text('Qty', col2X, tableTop)
            .text('Unit Price', col3X, tableTop, { width: 70, align: 'right' })
            .text('Tax Rate', col4X, tableTop, { width: 60, align: 'right' })
            .text('Line Total', col5X, tableTop, { width: 70, align: 'right' });

        doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, tableTop + 15).lineTo(550, tableTop + 15).stroke();

        let currentYPos = tableTop + 25;
        let subtotal = 0; // Subtotal before tax
        let totalTax = 0;

        quotationData.line_items.forEach(item => {
            // Check for page break before drawing item
            if (currentYPos + 20 > doc.page.height - doc.page.margins.bottom) {
                doc.addPage();
                currentYPos = doc.page.margins.top;
                // Redraw table headers on new page
                doc.fontSize(10).font('Helvetica-Bold')
                    .text('Description', col1X, currentYPos)
                    .text('Qty', col2X, currentYPos)
                    .text('Unit Price', col3X, currentYPos, { width: 70, align: 'right' })
                    .text('Tax Rate', col4X, currentYPos, { width: 60, align: 'right' })
                    .text('Line Total', col5X, currentYPos, { width: 70, align: 'right' });
                doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, currentYPos + 15).lineTo(550, currentYPos + 15).stroke();
                currentYPos += 25;
            }

            const itemDescription = item.product_service_name || item.description;
            const lineTotalWithTax = parseFloat(String(item.line_total)) || 0;
            const taxRate = parseFloat(String(item.tax_rate)) || 0;
            const unitPrice = parseFloat(String(item.unit_price)) || 0;
            const quantity = parseFloat(String(item.quantity)) || 0;

            let calculatedLineTotalExclTax = 0;
            let calculatedTaxAmount = 0;

            if (taxRate > 0) {
                // Assuming line_total includes tax if tax_rate > 0
                calculatedLineTotalExclTax = lineTotalWithTax / (1 + taxRate);
                calculatedTaxAmount = lineTotalWithTax - calculatedLineTotalExclTax;
            } else {
                calculatedLineTotalExclTax = lineTotalWithTax;
                calculatedTaxAmount = 0;
            }

            doc.fontSize(10).font('Helvetica')
                .text(itemDescription, col1X, currentYPos, { width: 190 }) // Matches invoice width for description
                .text(item.quantity.toString(), col2X, currentYPos, { width: 40, align: 'right' })
                .text(formatCurrency(unitPrice, quotationData.currency), col3X, currentYPos, { width: 70, align: 'right' })
                .text(`${(taxRate * 100).toFixed(2)}%`, col4X, currentYPos, { width: 60, align: 'right' })
                .text(formatCurrency(lineTotalWithTax, quotationData.currency), col5X, currentYPos, { width: 70, align: 'right' });
            
            currentYPos += 20; // Increment Y position for the next line item

            subtotal += calculatedLineTotalExclTax;
            totalTax += calculatedTaxAmount;
        });

        // Totals section - Matching Invoice Layout
        doc.moveDown();
        doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, currentYPos).lineTo(550, currentYPos).stroke();
        currentYPos += 10; // Space after the line

        // Display Subtotal and Tax similar to invoice if needed,
        // For now, I'll align the Total Amount as per invoice,
        // and add Subtotal/Tax above it to the right.
        
        // Subtotal (Right-aligned under the table)
        doc.fontSize(10).font('Helvetica')
           .text('Subtotal:', col4X, currentYPos, { width: 60, align: 'right' });
        doc.text(formatCurrency(subtotal, quotationData.currency), col5X, currentYPos, { width: 70, align: 'right' });
        currentYPos += 15; // Move down for next line

        // Total Tax (Right-aligned under the table)
        doc.fontSize(10).font('Helvetica')
           .text('Tax:', col4X, currentYPos, { width: 60, align: 'right' });
        doc.text(formatCurrency(totalTax, quotationData.currency), col5X, currentYPos, { width: 70, align: 'right' });
        currentYPos += 20; // Move down for final total with more space

        // Final Total Amount (Matches invoice's single line, right-aligned, with full currency)
        doc.fontSize(14).font('Helvetica-Bold')
            .text(`Total Amount: ${formatCurrency(quotationData.total_amount, quotationData.currency)}`, col1X, currentYPos, { align: 'right', width: 500 }); // Aligned to col1X, with width 500 to span right
        doc.moveDown(3);

        // Notes
        if (quotationData.notes) {
            doc.fontSize(10).font('Helvetica-Bold').text('Notes:');
            doc.font('Helvetica').fontSize(10).text(quotationData.notes, { align: 'left' });
            doc.moveDown(2);
        }

        // Footer
        doc.fontSize(10).text(`Thank you for considering our quotation!`, doc.page.width / 1, doc.page.height - 50, {
            align: 'left',
            width: doc.page.width - 100,
        });

        doc.end();
    });
}



// UPDATE the `/api/quotations/:id/pdf` endpoint
app.get('/api/quotations/:id/pdf', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id;

    try {
        const quotationQueryResult = await pool.query(
            `SELECT
                q.*,
                c.name AS customer_name,
                c.email AS customer_email,
                c.address AS customer_address
            FROM quotations q
            JOIN customers c ON q.customer_id = c.id
            WHERE q.id = $1 AND q.user_id = $2`,
            [id, user_id]
        );

        if (quotationQueryResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quotation not found' });
        }

        const quotation = quotationQueryResult.rows[0];

        // Fetch user's company information and logo path
        const userProfileResult = await pool.query(
            `SELECT company, address, city, province, postal_code, country, phone, email, company_logo_path
             FROM users WHERE user_id = $1`,
            [user_id]
        );
        const userCompany = userProfileResult.rows[0];
        let companyLogoUrl: string | null = null;
        if (userCompany && userCompany.company_logo_path) {
            const { data } = supabase.storage.from('company-logos').getPublicUrl(userCompany.company_logo_path);
            companyLogoUrl = data.publicUrl;
        }

        // Fetch line items for the quotation
        const lineItemsResult = await pool.query(
            `SELECT
                li.*,
                ps.name AS product_service_name
            FROM quotation_line_items li
            LEFT JOIN products_services ps ON li.product_service_id = ps.id
            WHERE li.quotation_id = $1
            ORDER BY li.created_at`,
            [id]
        );
        quotation.line_items = lineItemsResult.rows;

        // Prepare data for PDF generation, now including dynamic company info and logo URL
        const quotationDataForPdf = {
            ...quotation,
            total_amount: parseFloat(quotation.total_amount),
            line_items: quotation.line_items.map((item: any) => ({
                ...item,
                quantity: parseFloat(item.quantity),
                unit_price: parseFloat(item.unit_price),
                line_total: parseFloat(item.line_total),
                tax_rate: parseFloat(item.tax_rate),
            })),
            companyName: userCompany?.company || 'Your Company Name',
            companyAddress: userCompany?.address || null,
            companyCity: userCompany?.city || null,
            companyProvince: userCompany?.province || null,
            companyPostalCode: userCompany?.postal_code || null,
            companyCountry: userCompany?.country || null,
            companyPhone: userCompany?.phone || null,
            companyEmail: userCompany?.email || null,
            companyVat: userCompany?.vat_number || null,
            companyReg: userCompany?.reg_number || null,
            companyLogoUrl: companyLogoUrl, // NEW: Pass the logo URL to the PDF generator
        };

        const pdfBuffer = await generateQuotationPdf(quotationDataForPdf);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="quotation_${quotation.quotation_number}.pdf"`);
        res.send(pdfBuffer);
    } catch (error: unknown) {
        console.error(`Error generating quotation PDF:`, error);
        if (res.headersSent) {
            console.error('Headers already sent. Cannot send JSON error for PDF generation error.');
            return;
        }
        res.status(500).json({
            error: `Failed to generate quotation PDF`,
            details: error instanceof Error ? error.message : String(error)
        });
    }
});


// UPDATE the `/api/:documentType/:id/pdf` endpoint to include the logo

app.get('/api/:documentType/:id/pdf', authMiddleware, async (req: Request, res: Response) => {
    const { documentType, id } = req.params;
    const { startDate, endDate } = req.query;
    const user_id = req.user!.parent_user_id;

    // Fetch user's company information and logo path once
    const userProfileResult = await pool.query(
        `SELECT company, email, address, city, province, postal_code, country, phone, company_logo_path
         FROM users WHERE user_id = $1`,
        [user_id]
    );
    const userCompany = userProfileResult.rows[0];
    let companyLogoUrl: string | null = null;
    if (userCompany && userCompany.company_logo_path) {
        const { data } = supabase.storage.from('company-logos').getPublicUrl(userCompany.company_logo_path);
        companyLogoUrl = data.publicUrl;
    }

    const doc = new PDFDocument({ margin: 50 });

    try {
        switch (documentType) {
            case 'invoices':
            case 'invoice': {
                const invoiceQueryResult = await pool.query(
                    `SELECT
                        i.*,
                        c.name AS customer_name,
                        c.email AS customer_email
                    FROM invoices i
                    JOIN customers c ON i.customer_id = c.id
                    WHERE i.id = $1 AND i.user_id = $2`,
                    [id, user_id]
                );

                if (invoiceQueryResult.rows.length === 0) {
                    res.status(404).json({ error: 'Invoice not found' });
                    doc.end();
                    return;
                }

                const invoice = invoiceQueryResult.rows[0];

                res.setHeader('Content-Type', 'application/pdf');
                res.setHeader('Content-Disposition', `attachment; filename="invoice_${invoice.invoice_number}.pdf"`);

                doc.pipe(res);

                // Fetch line items
                const lineItemsResult = await pool.query(
                    `SELECT
                        li.*,
                        ps.name AS product_service_name
                    FROM invoice_line_items li
                    LEFT JOIN products_services ps ON li.product_service_id = ps.id
                    WHERE li.invoice_id = $1
                    ORDER BY li.created_at`,
                    [id]
                );
                invoice.line_items = lineItemsResult.rows;
                
                // --- PDF Content Generation for Invoice ---

                // Add the company logo and details
                let companyLogoBuffer: Buffer | null = null;
                let logoWidth = 120;
                const logoX = doc.page.width - doc.page.margins.right - logoWidth;

                if (companyLogoUrl) {
                    try {
                        const logoResponse = await axios.get(companyLogoUrl, { responseType: 'arraybuffer' });
                        companyLogoBuffer = Buffer.from(logoResponse.data, 'binary');
                        doc.image(companyLogoBuffer, logoX, 50, { width: logoWidth });
                    } catch (error) {
                        console.error('Failed to fetch company logo for PDF:', error);
                        // Continue generating PDF without the logo if fetch fails
                    }
                }

                // Company details - placed on the top-left side
                const companyDetailsY = 50;
                doc.fontSize(14).font('Helvetica-Bold').text(userCompany.company, 50, companyDetailsY);
                doc.moveDown(0.5);

                if (userCompany.address) {
                    doc.fontSize(10).font('Helvetica').text(userCompany.address);
                }
                const addressLine2 = [userCompany.city, userCompany.province, userCompany.postal_code, userCompany.country]
                    .filter(Boolean)
                    .join(', ');
                if (addressLine2) {
                    doc.text(addressLine2);
                }
                if (userCompany.phone) {
                    doc.text(`Phone: ${userCompany.phone}`);
                }
                if (userCompany.email) {
                    doc.text(`Email: ${userCompany.email}`);
                }
                if (userCompany.vat_number) {
                    doc.text(`VAT No: ${userCompany.vat_number}`);
                }
                if (userCompany.reg_number) {
                    doc.text(`Reg No: ${userCompany.reg_number}`);
                }

                doc.moveDown(2);

                // Invoice Title and Details on the right side
                doc.fontSize(30).font('Helvetica-Bold').text('INVOICE', { align: 'center' });
                doc.moveDown(1);
                doc.fontSize(12).font('Helvetica-Bold').text(`Invoice #${invoice.invoice_number}`, { align: 'center' });
                doc.fontSize(10).font('Helvetica')
                    .text(`Invoice Date: ${new Date(invoice.invoice_date).toLocaleDateString('en-GB')}`, { align: 'center' })
                    .text(`Due Date: ${new Date(invoice.due_date).toLocaleDateString('en-GB')}`, { align: 'center' });
                doc.moveDown(2);

                // Customer Details section
                doc.fontSize(12).font('Helvetica-Bold').text('Bill To:', 50, doc.y);
                doc.fontSize(10).font('Helvetica')
                    .text(invoice.customer_name, 50, doc.y + 15)
                    .text(invoice.customer_email, 50, doc.y + 30);
                doc.moveDown(2);

                // Line Items table
                const tableTop = doc.y;
                const col1X = 50;
                const col2X = 250;
                const col3X = 300;
                const col4X = 400;
                const col5X = 470;

                doc.fontSize(10)
                    .font('Helvetica-Bold')
                    .text('Description', col1X, tableTop)
                    .text('Qty', col2X, tableTop)
                    .text('Unit Price', col3X, tableTop, { width: 70, align: 'right' })
                    .text('Tax Rate', col4X, tableTop, { width: 60, align: 'right' })
                    .text('Line Total', col5X, tableTop, { width: 70, align: 'right' });

                doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, tableTop + 15).lineTo(550, tableTop + 15).stroke();

                let currentYPos = tableTop + 25;

                invoice.line_items.forEach((item: any) => {
                    if (currentYPos + 20 > doc.page.height - doc.page.margins.bottom) {
                        doc.addPage();
                        currentYPos = doc.page.margins.top;
                        doc.fontSize(10)
                            .font('Helvetica-Bold')
                            .text('Description', col1X, currentYPos)
                            .text('Qty', col2X, currentYPos)
                            .text('Unit Price', col3X, currentYPos, { width: 70, align: 'right' })
                            .text('Tax Rate', col4X, currentYPos, { width: 60, align: 'right' })
                            .text('Line Total', col5X, currentYPos, { width: 70, align: 'right' });
                        doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, currentYPos + 15).lineTo(550, currentYPos + 15).stroke();
                        currentYPos += 25;
                    }

                    doc.fontSize(10).font('Helvetica')
                        .text(item.description, col1X, currentYPos, { width: 190 })
                        .text(item.quantity.toString(), col2X, currentYPos, { width: 40, align: 'right' })
                        .text(`R${(parseFloat(item.unit_price)).toFixed(2)}`, col3X, currentYPos, { width: 70, align: 'right' })
                        .text(`${(parseFloat(item.tax_rate) * 100).toFixed(2)}%`, col4X, currentYPos, { width: 60, align: 'right' })
                        .text(`R${(parseFloat(item.line_total)).toFixed(2)}`, col5X, currentYPos, { width: 70, align: 'right' });
                    currentYPos += 20;
                });

                doc.moveDown();
                doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, currentYPos).lineTo(550, currentYPos).stroke();

                currentYPos += 10;
                doc.fontSize(14).font('Helvetica-Bold')
                    .text(`Total Amount: ${invoice.currency} ${(parseFloat(invoice.total_amount)).toFixed(2)}`, col1X, currentYPos, { align: 'right', width: 500 });

                if (invoice.notes) {
                    doc.moveDown(1.5);
                    doc.fontSize(10).font('Helvetica-Oblique').text(`Notes: ${invoice.notes}`);
                }

                doc.end();
                return;
            }

            case 'statement': {
                res.setHeader('Content-Type', 'application/pdf');
                doc.pipe(res);
                doc.text('Statement generation not fully implemented in this example.', { align: 'center' });
                doc.end();
                return;
            }

            default:
                res.status(400).json({ error: 'Document type not supported.' });
                doc.end();
                return;
        }

    } catch (error: unknown) {
        console.error(`Error generating ${documentType}:`, error);

        if (res.headersSent) {
            console.error('Headers already sent. Cannot send JSON error for PDF generation error.');
            doc.end();
            return;
        }

        res.status(500).json({
            error: `Failed to generate ${documentType}`,
            details: error instanceof Error ? error.message : String(error)
        });
        doc.end();
        return;
    }
});

// UPDATE the `/api/quotations/:id/send-pdf-email` endpoint

app.post('/api/quotations/:id/send-pdf-email', authMiddleware, upload.none(), async (req: Request, res: Response) => {
    const { id } = req.params;
    const { recipientEmail, subject, body } = req.body;
    const user_id = req.user!.parent_user_id;

    if (!recipientEmail || !subject || !body) {
        return res.status(400).json({ error: 'Recipient email, subject, and body are required.' });
    }

    try {
        // Fetch quotation details to generate PDF
        const quotationQueryResult = await pool.query(
            `SELECT
                q.*,
                c.name AS customer_name,
                c.email AS customer_email,
                c.address AS customer_address
            FROM quotations q
            JOIN customers c ON q.customer_id = c.id
            WHERE q.id = $1 AND q.user_id = $2`,
            [id, user_id]
        );

        if (quotationQueryResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quotation not found.' });
        }
        const quotation = quotationQueryResult.rows[0];

        // Fetch user's company information AND the logo path
        const userProfileResult = await pool.query(
            `SELECT company, address, city, province, postal_code, country, phone, email, company_logo_path -- <-- ADDED company_logo_path
             FROM users WHERE user_id = $1`,
            [user_id]
        );
        const userCompany = userProfileResult.rows[0]; // Use 'any' or define a proper type if needed
        let companyLogoUrl: string | null = null;
        if (userCompany && userCompany.company_logo_path) {
            // <-- GENERATE THE LOGO URL like in the download endpoint
            const { data } = supabase.storage.from('company-logos').getPublicUrl(userCompany.company_logo_path);
            companyLogoUrl = data.publicUrl;
        }


        const lineItemsResult = await pool.query(
            `SELECT
                li.*,
                ps.name AS product_service_name
            FROM quotation_line_items li
            LEFT JOIN products_services ps ON li.product_service_id = ps.id
            WHERE li.quotation_id = $1
            ORDER BY li.created_at`,
            [id]
        );
        quotation.line_items = lineItemsResult.rows;

        // Prepare data for PDF generation - INCLUDE companyLogoUrl
        const quotationDataForPdf: QuotationDetailsForPdf = {
            quotation_number: quotation.quotation_number,
            customer_name: quotation.customer_name,
            customer_email: quotation.customer_email,
            customer_address: quotation.customer_address,
            quotation_date: quotation.quotation_date,
            expiry_date: quotation.expiry_date,
            total_amount: parseFloat(quotation.total_amount),
            currency: quotation.currency,
            notes: quotation.notes,
            line_items: quotation.line_items.map((item: any) => ({
                product_service_name: item.product_service_name,
                description: item.description,
                quantity: parseFloat(item.quantity),
                unit_price: parseFloat(item.unit_price),
                line_total: parseFloat(item.line_total),
                tax_rate: parseFloat(item.tax_rate),
            })),
            companyName: userCompany?.company || 'Your Company Name',
            companyAddress: userCompany?.address || null,
            companyCity: userCompany?.city || null,
            companyProvince: userCompany?.province || null,
            companyPostalCode: userCompany?.postal_code || null,
            companyCountry: userCompany?.country || null,
            companyPhone: userCompany?.phone || null,
            companyEmail: userCompany?.email || null,
            companyVat: userCompany?.vat_number || null,
            companyReg: userCompany?.reg_number || null,
            companyLogoUrl: companyLogoUrl, // <-- PASS THE LOGO URL
        };

        // Generate PDF Buffer using the new function
        const pdfBuffer = await generateQuotationPdf(quotationDataForPdf);

        // Send email with PDF attachment
        const emailSent = await sendEmail({
            to: recipientEmail,
            subject: subject,
            html: body,
            attachments: [
                {
                    filename: `Quotation_${quotation.quotation_number}.pdf`,
                    content: pdfBuffer,
                    contentType: 'application/pdf',
                },
            ],
        });

        if (emailSent) {
            // Optional: Update quotation status to 'Sent' in your DB
            await pool.query(
                `UPDATE public.quotations SET status = 'Sent', updated_at = CURRENT_TIMESTAMP WHERE id = $1;`,
                [id]
            );
            res.status(200).json({ message: 'Email sent successfully!' });
        } else {
            res.status(500).json({ error: 'Failed to send quotation email.' });
        }

    } catch (error: unknown) {
        console.error('Error in send-pdf-email endpoint:', error);
        if (res.headersSent) {
            console.error('Headers already sent in send-pdf-email. Cannot send JSON error.');
            return;
        }
        if (error instanceof Error) {
            res.status(500).json({ error: 'Failed to process email request', details: error.message });
        } else {
            res.status(500).json({ error: 'Failed to process email request', details: String(error) });
        }
    }
});

/* --- Transactions API (Fetching) --- */
app.get('/transactions', authMiddleware, async (req: Request, res: Response) => {
  const { type, category, accountId, search, fromDate, toDate, since, limit } = req.query as {
    type?: string;
    category?: string;
    accountId?: string;
    search?: string;
    fromDate?: string;
    toDate?: string;
    since?: string;
    limit?: string;
  };

  // Prefer company scoping, fallback to user_id
  const user_id = (req.user!.parent_user_id || req.user!.user_id)!;

  // Validate date range if provided
  if (fromDate && toDate) {
    const parsedFromDate = new Date(fromDate);
    const parsedToDate = new Date(toDate);
    if (parsedFromDate > parsedToDate) {
      console.warn(`Invalid date range: fromDate (${fromDate}) > toDate (${toDate}). Returning empty list.`);
      return res.json([]);
    }
  }

  // Limit results for performance; default 500, max 2000
  const safeLimit = Math.min(Math.max(parseInt(limit || '500', 10) || 500, 1), 2000);

  let query = `
    SELECT
      t.id,
      t.type,
      t.amount,
      t.description,
      t.date,
      t.category,
      t.created_at,
      t.account_id,
      t.original_text,
      t.source,
      t.confirmed,
      acc.name AS account_name,
      acc.type AS account_type
    FROM transactions t
    LEFT JOIN accounts acc ON t.account_id = acc.id
    WHERE t.user_id = $1
  `;

  const queryParams: (string | number)[] = [user_id];
  let paramIndex = 2;

  // Filters
  if (type && type !== 'all') {
    query += ` AND t.type = $${paramIndex++}`;
    queryParams.push(type);
  }

  if (category && category !== 'all') {
    query += ` AND t.category = $${paramIndex++}`;
    queryParams.push(category);
  }

  if (accountId && accountId !== 'all') {
    query += ` AND t.account_id = $${paramIndex++}`;
    queryParams.push(accountId);
  }

  if (search) {
    // BUGFIX: increment paramIndex after pushing the search param
    query += ` AND (t.description ILIKE $${paramIndex} OR t.type ILIKE $${paramIndex} OR acc.name ILIKE $${paramIndex})`;
    queryParams.push(`%${search}%`);
    paramIndex++; // <-- important so later params don't reuse the same placeholder
  }

  // Date windowing
  if (fromDate) {
    query += ` AND t.date >= $${paramIndex++}`;
    queryParams.push(fromDate);
  }

  if (toDate) {
    query += ` AND t.date <= $${paramIndex++}`;
    queryParams.push(toDate);
  }

  // NEW: `since` shortcut for duplicate-check fetches (only applied if fromDate is not supplied)
  if (!fromDate && since) {
    query += ` AND t.date >= $${paramIndex++}`;
    queryParams.push(since);
  }

  query += ` ORDER BY t.date DESC, t.created_at DESC LIMIT ${safeLimit}`;

  try {
    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error: unknown) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({
      error: 'Failed to fetch transactions',
      detail: error instanceof Error ? error.message : String(error),
    });
  }
});

// ---- money helpers (server-side) ----
const toNum = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
};

/**
 * Formats amounts for PDFs/HTML. Accepts:
 *  - ISO currency like 'ZAR', 'USD'
 *  - local symbol like 'R'
 *  - empty/undefined -> defaults to South Africa Rand symbol 'R'
 *
 * Examples:
 *  formatCurrency(1234.5, 'ZAR') -> "R 1,234.50"
 *  formatCurrency(1234.5, 'R')   -> "R1,234.50"
 *  formatCurrency('1234.5', '')  -> "R1,234.50"
 */
function formatCurrency(amount: number | string | null | undefined, currency?: string): string {
  const val = toNum(amount);
  const cur = (currency || '').trim().toUpperCase();

  // If an ISO code is given (e.g., ZAR/USD/EUR), use Intl currency formatting
  if (cur && cur.length === 3) {
    try {
      return new Intl.NumberFormat('en-ZA', {
        style: 'currency',
        currency: cur,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(val);
    } catch {
      // fall through to symbol formatting if Intl rejects the code
    }
  }

  // Otherwise, assume symbol formatting (default 'R')
  const symbol = (currency && currency.trim()) ? currency.trim() : 'R';
  return `${symbol}${val.toLocaleString('en-ZA', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

// ADD THE NEW DELETE ENDPOINT HERE
app.delete('/transactions/:id', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;

    // Prefer company scoping, fallback to user_id
    const user_id = (req.user!.parent_user_id || req.user!.user_id)!;

    // Start a database client for transaction
    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // Start the transaction

        // 1. Delete dependent depreciation entries first
        const deleteDepreciationQuery = `
            DELETE FROM depreciation_entries
            WHERE transaction_id = $1 AND user_id = $2;
        `;
        await client.query(deleteDepreciationQuery, [id, user_id]);
        console.log(`Deleted depreciation entries for transaction ID: ${id}`);

        // 2. Then, delete the transaction itself
        const deleteTransactionQuery = `
            DELETE FROM transactions
            WHERE id = $1 AND user_id = $2
            RETURNING id; 
        `;
        const result = await client.query(deleteTransactionQuery, [id, user_id]);

        if (result.rowCount === 0) {
            await client.query('ROLLBACK'); // Rollback if transaction not found or unauthorized
            return res.status(404).json({ error: 'Transaction not found or unauthorized' });
        }

        await client.query('COMMIT'); // Commit the transaction if both succeeded
        console.log(`Transaction ID: ${id} and its depreciation entries deleted successfully.`);
        res.status(204).send(); // 204 No Content is standard for a successful DELETE

    } catch (error: unknown) {
        await client.query('ROLLBACK'); // Rollback on any error
        console.error('Error deleting transaction (and associated depreciation entries):', error);
        res.status(500).json({
            error: 'Failed to delete transaction',
            detail: error instanceof Error ? error.message : String(error),
        });
    } finally {
        client.release(); // Always release the client back to the pool
    }
});


/* --- Accounts API --- */
app.get('/accounts', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.parent_user_id;
  try {
    // --- UPDATE THE QUERY TO SELECT THE REQUIRED FIELDS ---
    const result = await pool.query(
      `SELECT id, name, type, code, is_postable, is_active, reporting_category_id
         FROM accounts
        WHERE user_id = $1
        ORDER BY code ASC, name ASC`,
      [user_id]
    );
    res.json(result.rows);
  } catch (error: unknown) {
    console.error('Error fetching accounts:', error);
    res.status(500).json({ error: 'Failed to fetch accounts', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.post('/accounts', authMiddleware, async (req: Request, res: Response) => {
  const { type, name, code } = req.body;
  const user_id = req.user!.parent_user_id;

  if (!type || !name || !code) {
    return res.status(400).json({ error: 'Missing required account fields: type, name, code' });
  }

  try {
    // Enforce unique (user_id, code)
    const dupe = await pool.query(`SELECT 1 FROM accounts WHERE user_id = $1 AND code = $2 LIMIT 1`, [user_id, code]);
    if (dupe.rowCount) {
      return res.status(409).json({ error: `Account code ${code} already exists.` });
    }

const insert = await pool.query(
  `INSERT INTO accounts (type, name, code, user_id) -- Consider adding defaults for is_active etc. if needed
   VALUES ($1, $2, $3, $4)
   RETURNING id, name, type, code, is_postable, is_active, reporting_category_id`, // <-- Updated RETURNING
  [type, name, code, user_id]
);
res.status(201).json(insert.rows[0]);

    res.status(201).json(insert.rows[0]);
  } catch (error: unknown) {
    console.error('Error adding account:', error);
    res.status(500).json({ error: 'Failed to add account', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.put('/accounts/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { type, name, code } = req.body as Partial<{ type: string; name: string; code: string }>;
  const user_id = req.user!.parent_user_id;

  if (!type && !name && !code) {
    return res.status(400).json({ error: 'Provide at least one field to update: type, name, or code' });
  }

  try {
    // Ensure the account belongs to this user
    const exists = await pool.query(`SELECT id, code FROM accounts WHERE id = $1 AND user_id = $2`, [id, user_id]);
    if (!exists.rowCount) return res.status(404).json({ error: 'Account not found' });

    // If changing code, enforce unique per user
    if (code) {
      const dupe = await pool.query(
        `SELECT 1 FROM accounts WHERE user_id = $1 AND code = $2 AND id <> $3 LIMIT 1`,
        [user_id, code, id]
      );
      if (dupe.rowCount) {
        return res.status(409).json({ error: `Account code ${code} already exists.` });
      }
    }

    // Build dynamic update
    const fields: string[] = [];
    const values: any[] = [];
    let idx = 1;

    if (type) { fields.push(`type = $${idx++}`); values.push(type); }
    if (name) { fields.push(`name = $${idx++}`); values.push(name); }
    if (code) { fields.push(`code = $${idx++}`); values.push(code); }

    values.push(id, user_id);

    const updated = await pool.query(
      `UPDATE accounts
          SET ${fields.join(', ')},
              updated_at = NOW()
        WHERE id = $${idx++} AND user_id = $${idx}
        RETURNING id, name, type, code`,
      values
    );

    res.json(updated.rows[0]);
  } catch (error: unknown) {
    console.error('Error updating account:', error);
    res.status(500).json({ error: 'Failed to update account', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.delete('/accounts/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const user_id = req.user!.parent_user_id;

  try {
    // Owns account?
    const acct = await pool.query(`SELECT id FROM accounts WHERE id = $1 AND user_id = $2`, [id, user_id]);
    if (!acct.rowCount) return res.status(404).json({ error: 'Account not found' });

    // Block delete if referenced
    const [tx, as, ex] = await Promise.all([
      pool.query(`SELECT 1 FROM transactions WHERE account_id = $1 LIMIT 1`, [id]),
      pool.query(`SELECT 1 FROM assets       WHERE account_id = $1 LIMIT 1`, [id]),
      pool.query(`SELECT 1 FROM expenses     WHERE account_id = $1 LIMIT 1`, [id]),
    ]);

    if (tx.rowCount || as.rowCount || ex.rowCount) {
      return res.status(409).json({
        error: 'Account is in use',
        detail: 'This account has linked transactions/assets/expenses. Reassign or delete those first.'
      });
    }

    await pool.query(`DELETE FROM accounts WHERE id = $1 AND user_id = $2`, [id, user_id]);
    res.status(204).send();
  } catch (error: unknown) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Failed to delete account', detail: error instanceof Error ? error.message : String(error) });
  }
});



// The interface is updated to correctly handle potential null values from the database
interface InvoiceDetailsForPdf {
    invoice_number: string;
    customer_name: string;
    customer_email?: string | null;
    customer_address?: string | null;
    invoice_date: string;
    due_date: string;
    total_amount: number;
    currency: string;
    notes?: string | null;
    line_items: Array<{
        product_service_name?: string | null;
        description: string;
        quantity: number;
        unit_price: number;
        line_total: number;
        tax_rate: number;
    }>;
    companyName: string; // From your .env or DB
    companyAddress?: string | null;
    companyCity?: string | null; // <-- ADDED THIS
    companyProvince?: string | null; // <-- ADDED THIS
    companyPostalCode?: string | null; // <-- ADDED THIS
    companyCountry?: string | null; // <-- ADDED THIS
    companyEmail?: string | null;
    companyPhone?: string | null;
    companyVat?: string | null;
    companyReg?: string | null;
}

async function generateInvoicePdf(invoiceData: InvoiceDetailsForPdf): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 50 });
        const buffers: Buffer[] = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        doc.on('error', reject);

        // Header
        // This is where the companyName will be used.
        doc.fontSize(24).font('Helvetica-Bold').text(invoiceData.companyName, { align: 'right' });
        if (invoiceData.companyAddress) {
            doc.fontSize(10).font('Helvetica').text(invoiceData.companyAddress, { align: 'right' });
        }
        if (invoiceData.companyVat) {
            doc.fontSize(10).font('Helvetica').text(`VAT No: ${invoiceData.companyVat}`, { align: 'right' });
        }
        doc.moveDown(1);
        doc.fontSize(10).text(`Invoice Date: ${new Date(invoiceData.invoice_date).toLocaleDateString('en-ZA')}`, { align: 'right' });
        doc.fontSize(10).text(`Due Date: ${new Date(invoiceData.due_date).toLocaleDateString('en-ZA')}`, { align: 'right' });
        doc.moveDown(2);

        // Title
        doc.fontSize(30).font('Helvetica-Bold').text(`INVOICE #${invoiceData.invoice_number}`, { align: 'center' });
        doc.moveDown(2);

        // Bill To
        doc.fontSize(12).font('Helvetica-Bold').text('Bill To:');
        doc.fontSize(12).font('Helvetica').text(invoiceData.customer_name);
        if (invoiceData.customer_address) {
            doc.fontSize(10).text(invoiceData.customer_address);
        }
        if (invoiceData.customer_email) {
            doc.fontSize(10).text(invoiceData.customer_email);
        }
        doc.moveDown(2);

        // Table Header
        const tableTop = doc.y;
        const itemCol = 50;
        const descCol = 150;
        const qtyCol = 320;
        const priceCol = 370;
        const taxCol = 430;
        const totalCol = 500;

        doc.font('Helvetica-Bold').fontSize(10);
        doc.text('Item', itemCol, tableTop);
        doc.text('Description', descCol, tableTop);
        doc.text('Qty', qtyCol, tableTop, { width: 50, align: 'right' });
        doc.text('Price', priceCol, tableTop, { width: 50, align: 'right' });
        doc.text('Tax', taxCol, tableTop, { width: 50, align: 'right' });
        doc.text('Total', totalCol, tableTop, { width: 50, align: 'right' });

        doc.strokeColor('#aaaaaa').lineWidth(1).moveTo(itemCol, tableTop + 15).lineTo(doc.page.width - 50, tableTop + 15).stroke();
        doc.moveDown();

        // Table Body
        doc.font('Helvetica').fontSize(9);
        let currentY = doc.y;
        let subtotal = 0;
        let totalTax = 0;

        invoiceData.line_items.forEach(item => {
            currentY = doc.y;
            const itemDescription = item.product_service_name || item.description;
            const taxAmount = (item.line_total * item.tax_rate);
            const lineTotalExclTax = item.line_total - taxAmount;

            doc.text(itemDescription, itemCol, currentY, { width: 140 });
            doc.text(item.description, descCol, currentY, { width: 160 }); // Full description if needed
            doc.text(item.quantity.toString(), qtyCol, currentY, { width: 50, align: 'right' });
            doc.text(formatCurrency(item.unit_price, ''), priceCol, currentY, { width: 50, align: 'right' });
            doc.text(`${(item.tax_rate * 100).toFixed(0)}%`, taxCol, currentY, { width: 50, align: 'right' });
            doc.text(formatCurrency(item.line_total, ''), totalCol, currentY, { width: 50, align: 'right' });

            doc.moveDown();
            subtotal += lineTotalExclTax;
            totalTax += taxAmount;
        });

        // Totals
        doc.moveDown();
        const totalsY = doc.y;
        doc.font('Helvetica-Bold').fontSize(10);

        doc.text('Subtotal:', 400, totalsY, { width: 80, align: 'right' });
        doc.text(formatCurrency(subtotal, invoiceData.currency), 500, totalsY, { width: 50, align: 'right' });
        doc.moveDown();

        doc.text('Tax:', 400, doc.y, { width: 80, align: 'right' });
        doc.text(formatCurrency(totalTax, invoiceData.currency), 500, doc.y, { width: 50, align: 'right' });
        doc.moveDown();

        doc.fontSize(14).text('Total Due:', 400, doc.y, { width: 80, align: 'right' });
        doc.text(formatCurrency(invoiceData.total_amount, invoiceData.currency), 500, doc.y, { width: 50, align: 'right' });
        doc.moveDown(3);

        // Notes
        if (invoiceData.notes) {
            doc.fontSize(10).font('Helvetica-Bold').text('Notes:');
            doc.font('Helvetica').fontSize(10).text(invoiceData.notes, { align: 'left' });
            doc.moveDown(2);
        }

        // Footer
        doc.fontSize(10).text(`Thank you for your business!`, doc.page.width / 2, doc.page.height - 50, {
            align: 'center',
            width: doc.page.width - 100,
        });

        doc.end();
    });
}

app.post('/api/invoices/:id/send-pdf-email', authMiddleware, async (req: Request, res: Response) => {
    const invoiceId = req.params.id;
    const { customerEmail } = req.body;
    const user_id = req.user!.parent_user_id;

    if (!customerEmail) {
        return res.status(400).json({ error: 'Customer email is required to send the invoice.' });
    }

    try {
        // 1. Fetch Invoice Details from Database (including line items and customer info)
        const invoiceResult = await pool.query(
            `SELECT
                i.id, i.invoice_number, i.invoice_date, i.due_date, i.total_amount, i.status, i.currency, i.notes,
                c.name AS customer_name, c.email AS customer_email, c.address AS customer_address
            FROM public.invoices i
            JOIN public.customers c ON i.customer_id = c.id
            WHERE i.id = $1 AND i.user_id = $2;`,
            [invoiceId, user_id]
        );

        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found.' });
        }
        const invoice = invoiceResult.rows[0];

        const lineItemsResult = await pool.query(
            `SELECT
                il.product_service_id, il.description, il.quantity, il.unit_price, il.line_total, il.tax_rate,
                ps.name AS product_service_name
            FROM public.invoice_line_items il
            LEFT JOIN public.products_services ps ON il.product_service_id = ps.id
            WHERE il.invoice_id = $1;`,
            [invoiceId]
        );
        invoice.line_items = lineItemsResult.rows;

        // 2. FETCH THE USER'S COMPANY PROFILE
        // This is a crucial step to get the user's company information from the database
        const userProfileResult = await pool.query(
            'SELECT company, address, city, province, postal_code, country FROM public.users WHERE user_id = $1;',
            [user_id]
        );

        const userProfile = userProfileResult.rows[0];
        const companyName = userProfile?.company || 'Your Company';
        // Dynamically construct the full company address string
        const companyAddress = userProfile?.address ?
            `${userProfile.address}, ${userProfile.city}, ${userProfile.province}, ${userProfile.postal_code}, ${userProfile.country}`
            : null;

        // 3. Prepare data for PDF generation, now including dynamic company info
        const invoiceDataForPdf: InvoiceDetailsForPdf = {
            invoice_number: invoice.invoice_number,
            customer_name: invoice.customer_name,
            customer_email: invoice.customer_email,
            customer_address: invoice.customer_address,
            invoice_date: invoice.invoice_date,
            due_date: invoice.due_date,
            total_amount: parseFloat(invoice.total_amount),
            currency: invoice.currency,
            notes: invoice.notes,
            line_items: invoice.line_items.map((item: any) => ({
                product_service_name: item.product_service_name,
                description: item.description,
                quantity: parseFloat(item.quantity),
                unit_price: parseFloat(item.unit_price),
                line_total: parseFloat(item.line_total),
                tax_rate: parseFloat(item.tax_rate),
            })),
            companyName: companyName, // USE DYNAMIC COMPANY NAME
            companyAddress: companyAddress, // USE DYNAMIC COMPANY ADDRESS
            companyVat: null, // Placeholder for VAT number
        };

        // 4. Generate PDF
        const pdfBuffer = await generateInvoicePdf(invoiceDataForPdf);

        // 5. Send Email with PDF attachment, also using dynamic company name
        const emailSubject = `Invoice #${invoice.invoice_number} from ${companyName}`;
        const emailHtml = `
            <p>Dear ${invoice.customer_name},</p>
            <p>Please find attached your invoice (Invoice ID: <b>#${invoice.invoice_number}</b>) from ${companyName}.</p>
            <p>Total amount due: <b>${formatCurrency(invoiceDataForPdf.total_amount, invoiceDataForPdf.currency)}</b></p>
            <p>Due Date: ${new Date(invoice.due_date).toLocaleDateString('en-ZA')}</p>
            <p>Thank you for your business!</p>
            <p>Sincerely,<br>${companyName}</p>
        `;

        const emailSent = await sendEmail({
            to: customerEmail,
            subject: emailSubject,
            html: emailHtml,
            attachments: [
                {
                    filename: `Invoice_${invoice.invoice_number}.pdf`,
                    content: pdfBuffer,
                    contentType: 'application/pdf',
                },
            ],
        });

        if (emailSent) {
            // Optional: Update invoice status to 'Sent' in your DB
            await pool.query(
                `UPDATE public.invoices SET status = 'Sent', updated_at = CURRENT_TIMESTAMP WHERE id = $1;`,
                [invoiceId]
            );
            res.status(200).json({ message: 'Invoice PDF generated and email sent successfully!' });
        } else {
            res.status(500).json({ error: 'Failed to send invoice email.' });
        }

    } catch (error: any) {
        console.error('Error generating PDF or sending email:', error);
        res.status(500).json({
            error: 'Failed to generate PDF or send email.',
            detail: error.message || String(error)
        });
    }
});

/* --- Assets API --- */

// Updated Asset Interface to include depreciation fields
interface Asset {
  id: string;
  type: string;
  name: string;
  number?: string;
  cost: number;
  date_received: string;
  account_id: string;
  account_name: string;
  depreciation_method?: string; // New
  useful_life_years?: number;   // New
  salvage_value?: number;       // New
  accumulated_depreciation: number; // New
  last_depreciation_date?: string; // New
}

app.get('/assets', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    const result = await pool.query(`
      SELECT
        a.id,
        a.type,
        a.name,
        a.number,
        a.cost,
        a.date_received,
        a.account_id,
        acc.name AS account_name,
        a.depreciation_method,      
        a.useful_life_years,        
        a.salvage_value,            
        a.accumulated_depreciation, 
        a.last_depreciation_date    
      FROM assets a
      JOIN accounts acc ON a.account_id = acc.id
      WHERE a.user_id = $1 -- ADDED user_id filter
      ORDER BY a.date_received DESC
    `, [user_id]);
    res.json(result.rows);
  } catch (error: unknown) {
    console.error('Error fetching assets:', error);
    res.status(500).json({ error: 'Failed to fetch assets', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.post('/assets', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const {
    type, name, number, cost, date_received, account_id,
    depreciation_method, useful_life_years, salvage_value
  } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!type || !name || cost == null || !date_received || !account_id) {
    return res.status(400).json({ error: 'Missing required asset fields: type, name, cost, date_received, account_id' });
  }

  try {
    const insert = await pool.query(
      `INSERT INTO assets (
        type, name, number, cost, date_received, account_id,
        depreciation_method, useful_life_years, salvage_value, accumulated_depreciation, last_depreciation_date, user_id
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`, // ADDED user_id
      [
        type, name, number || null, cost, date_received, account_id,
        depreciation_method || null, useful_life_years || null, salvage_value || null,
        0.00, // Initialize accumulated_depreciation to 0
        null,  // Initialize last_depreciation_date to null
        user_id // ADDED user_id
      ]
    );
    const insertedId = insert.rows[0].id;

    const fullAsset = await pool.query(`
      SELECT
        a.id, a.type, a.name, a.number, a.cost, a.date_received, a.account_id, acc.name AS account_name,
        a.depreciation_method, a.useful_life_years, a.salvage_value, a.accumulated_depreciation, a.last_depreciation_date
      FROM assets a
      JOIN accounts acc ON a.account_id = acc.id
      WHERE a.id = $1 AND a.user_id = $2 -- ADDED user_id filter
    `, [insertedId, user_id]);

    res.json(fullAsset.rows[0]);
  } catch (error: unknown) {
    console.error('Error adding asset:', error);
    res.status(500).json({ error: 'Failed to add asset', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.put('/assets/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { id } = req.params;
  const {
    type, name, number, cost, date_received, account_id,
    depreciation_method, useful_life_years, salvage_value, accumulated_depreciation, last_depreciation_date
  } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  const updates = [];
  const values = [];
  let paramIndex = 1;

  if (type !== undefined) { updates.push(`type = $${paramIndex++}`); values.push(type); }
  if (name !== undefined) { updates.push(`name = $${paramIndex++}`); values.push(name); }
  if (number !== undefined) { updates.push(`number = $${paramIndex++}`); values.push(number || null); }
  if (cost !== undefined) { updates.push(`cost = $${paramIndex++}`); values.push(cost); }
  if (date_received !== undefined) { updates.push(`date_received = $${paramIndex++}`); values.push(date_received); }
  if (account_id !== undefined) { updates.push(`account_id = $${paramIndex++}`); values.push(account_id); }
  if (depreciation_method !== undefined) { updates.push(`depreciation_method = $${paramIndex++}`); values.push(depreciation_method || null); }
  if (useful_life_years !== undefined) { updates.push(`useful_life_years = $${paramIndex++}`); values.push(useful_life_years || null); }
  if (salvage_value !== undefined) { updates.push(`salvage_value = $${paramIndex++}`); values.push(salvage_value || null); }
  if (accumulated_depreciation !== undefined) { updates.push(`accumulated_depreciation = $${paramIndex++}`); values.push(accumulated_depreciation); }
  if (last_depreciation_date !== undefined) { updates.push(`last_depreciation_date = $${paramIndex++}`); values.push(last_depreciation_date || null); }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields provided for update.' });
  }

  values.push(id); // Add ID for WHERE clause
  values.push(user_id); // ADDED user_id for WHERE clause

  try {
    const result = await pool.query(
      `UPDATE assets SET ${updates.join(', ')} WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1} RETURNING *`, // ADDED user_id filter
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Asset not found or unauthorized' });
    }
    res.json(result.rows[0]);
  } catch (error: unknown) {
    console.error('Error updating asset:', error);
    res.status(500).json({ error: 'Failed to update asset', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.delete('/assets/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { id } = req.params;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    const result = await pool.query('DELETE FROM assets WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Asset not found or unauthorized' });
    }
    res.json({ message: 'Asset deleted successfully' });
  } catch (error: unknown) {
    console.error('Error deleting asset:', error);
    res.status(500).json({ error: 'Failed to delete asset', detail: error instanceof Error ? error.message : String(error) });
  }
});


/* --- Depreciation API --- */

// Helper function to calculate straight-line depreciation for a period
const calculateDepreciation = (
  cost: number,
  salvageValue: number,
  usefulLifeYears: number,
  startDate: Date,
  endDate: Date
): number => {
  if (usefulLifeYears <= 0) return 0;

  const depreciableBase = cost - salvageValue;
  const annualDepreciation = depreciableBase / usefulLifeYears;
  const monthlyDepreciation = annualDepreciation / 12;

  // Calculate number of months in the period
  let monthsToDepreciate = 0;
  let currentMonth = new Date(startDate.getFullYear(), startDate.getMonth(), 1);

  while (currentMonth <= endDate) {
    monthsToDepreciate++;
    currentMonth.setMonth(currentMonth.getMonth() + 1);
  }

  return monthlyDepreciation * monthsToDepreciate;
};


app.post('/api/depreciation/run', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { endDate } = req.body; // endDate: The date up to which depreciation should be calculated
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!endDate) {
    return res.status(400).json({ error: 'endDate is required for depreciation calculation.' });
  }

  const calculationEndDate = new Date(endDate);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Fetch all assets that are depreciable and haven't been depreciated up to the endDate
    const assetsResult = await client.query(`
      SELECT
        id, cost, useful_life_years, salvage_value, date_received, accumulated_depreciation, last_depreciation_date
      FROM assets
      WHERE
        user_id = $1 AND -- ADDED user_id filter
        depreciation_method = 'straight-line' AND useful_life_years IS NOT NULL AND useful_life_years > 0
        AND (last_depreciation_date IS NULL OR last_depreciation_date < $2)
    `, [user_id, calculationEndDate.toISOString().split('T')[0]]); // Compare only date part

    const depreciatedAssets: { assetId: number; amount: number; transactionId: number }[] = [];
    let totalDepreciationExpense = 0;
    let defaultExpenseAccountId: number | null = null;

    // Try to find a suitable account for depreciation expense (e.g., 'Depreciation Expense' or 'Other Expenses')
    const expenseAccountResult = await client.query(
      `SELECT id FROM accounts WHERE (name ILIKE 'Depreciation Expense' OR name ILIKE 'Other Expenses') AND user_id = $1 LIMIT 1`, // ADDED user_id filter
      [user_id]
    );
    if (expenseAccountResult.rows.length > 0) {
      defaultExpenseAccountId = expenseAccountResult.rows[0].id;
    } else {
      await client.query('ROLLBACK');
      return res.status(500).json({ error: 'Could not find a suitable expense account for depreciation for this user.' });
    }

    for (const asset of assetsResult.rows) {
      const assetCost = parseFloat(asset.cost);
      const assetSalvageValue = parseFloat(asset.salvage_value || 0);
      const assetUsefulLifeYears = parseInt(asset.useful_life_years, 10);
      const assetDateReceived = new Date(asset.date_received);
      const assetLastDepreciationDate = asset.last_depreciation_date ? new Date(asset.last_depreciation_date) : null;

      // Determine the start date for this depreciation calculation
      // It's either the day after last_depreciation_date, or date_received if no prior depreciation
      let depreciationStartDate = assetLastDepreciationDate
        ? new Date(assetLastDepreciationDate.getFullYear(), assetLastDepreciationDate.getMonth(), assetLastDepreciationDate.getDate() + 1)
        : assetDateReceived;

      // Ensure depreciation doesn't start before the asset was received
      if (depreciationStartDate < assetDateReceived) {
        depreciationStartDate = assetDateReceived;
      }

      // Ensure we don't depreciate beyond the useful life
      const usefulLifeEndDate = new Date(assetDateReceived.getFullYear() + assetUsefulLifeYears, assetDateReceived.getMonth(), assetDateReceived.getDate());
      if (depreciationStartDate >= usefulLifeEndDate) {
          console.log(`Asset ${asset.id} has reached end of useful life or already fully depreciated.`);
          continue; // Skip if already fully depreciated or beyond useful life
      }

      // Adjust calculationEndDate if it's beyond the useful life end date
      let effectiveCalculationEndDate = calculationEndDate;
      if (effectiveCalculationEndDate > usefulLifeEndDate) {
          effectiveCalculationEndDate = usefulLifeEndDate;
      }

      // Calculate depreciation only if the period is valid
      if (depreciationStartDate <= effectiveCalculationEndDate) {
        const depreciationAmount = calculateDepreciation(
          assetCost,
          assetSalvageValue,
          assetUsefulLifeYears,
          depreciationStartDate,
          effectiveCalculationEndDate
        );

        if (depreciationAmount > 0) {
          // 1. Update accumulated_depreciation on the asset
          const newAccumulatedDepreciation = parseFloat(asset.accumulated_depreciation) + depreciationAmount;
          await client.query(
            `UPDATE assets SET accumulated_depreciation = $1, last_depreciation_date = $2 WHERE id = $3 AND user_id = $4`, // ADDED user_id filter
            [newAccumulatedDepreciation, effectiveCalculationEndDate.toISOString().split('T')[0], asset.id, user_id]
          );

          // 2. Create a transaction for depreciation expense
          const transactionResult = await client.query(
            `INSERT INTO transactions (type, amount, description, date, category, account_id, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, // ADDED user_id
            [
              'expense',
              depreciationAmount,
              `Depreciation Expense for ${asset.name} (ID: ${asset.id})`,
              effectiveCalculationEndDate.toISOString().split('T')[0], // Use end date of calculation period
              'Depreciation Expense', // Use a specific category for depreciation
              defaultExpenseAccountId, // Link to a general expense account
              user_id // ADDED user_id
            ]
          );
          const transactionId = transactionResult.rows[0].id;

          // 3. Record the depreciation entry
          await client.query(
            `INSERT INTO depreciation_entries (asset_id, depreciation_date, amount, transaction_id, user_id)
             VALUES ($1, $2, $3, $4, $5)`, // ADDED user_id
            [asset.id, effectiveCalculationEndDate.toISOString().split('T')[0], depreciationAmount, transactionId, user_id]
          );

          totalDepreciationExpense += depreciationAmount;
          depreciatedAssets.push({ assetId: asset.id, amount: depreciationAmount, transactionId: transactionId });
        }
      }
    }

    await client.query('COMMIT');
    res.json({
      message: 'Depreciation calculated and recorded successfully.',
      totalDepreciationExpense: totalDepreciationExpense,
      depreciatedAssets: depreciatedAssets
    });

  } catch (error: unknown) {
    await client.query('ROLLBACK');
    console.error('Error running depreciation:', error);
    res.status(500).json({ error: 'Failed to run depreciation', detail: error instanceof Error ? error.message : String(error) });
  } finally {
    client.release();
  }
});


/* --- Expenses API --- */
app.get('/expenses', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    // Select all fields relevant for an expense transaction + account_name
    const result = await pool.query(`
      SELECT e.id, e.name, e.details, e.category, e.amount, e.date, e.account_id, acc.name AS account_name
      FROM expenses e
      JOIN accounts acc ON e.account_id = acc.id
      WHERE e.user_id = $1 -- ADDED user_id filter
      ORDER BY e.date DESC
    `, [user_id]);
    res.json(result.rows);
  } catch (error: unknown) { // Changed 'err' to 'error: unknown'
    console.error('Error fetching expenses:', error);
    res.status(500).json({ error: 'Failed to fetch expenses', detail: error instanceof Error ? error.message : String(error) });
  }
});

app.post('/expenses', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  // Ensure all required fields for an expense transaction are captured
  const { name, details, category, amount, date, account_id } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!name || amount == null || !date || !account_id) {
    return res.status(400).json({ error: 'Missing required expense fields: name, amount, date, account_id' });
  }

  try {
    const insert = await pool.query(
      `INSERT INTO expenses (name, details, category, amount, date, account_id, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, // ADDED user_id
      // Ensure details and category are correctly handled for nullable columns
      [name, details || null, category || null, amount, date, account_id, user_id]
    );
    const insertedId = insert.rows[0].id;

    const fullExpense = await pool.query(`
      SELECT e.id, e.name, e.details, e.category, e.amount, e.date, e.account_id, acc.name AS account_name
      FROM expenses e
      JOIN accounts acc ON e.account_id = acc.id
      WHERE e.id = $1 AND e.user_id = $2 -- ADDED user_id filter
    `, [insertedId, user_id]);

    res.json(fullExpense.rows[0]);
  } catch (error: unknown) { // Changed 'err' to 'error: unknown'
    console.error('Error adding expense:', error);
    res.status(500).json({ error: 'Failed to add expense', detail: error instanceof Error ? error.message : String(error) });
  }
});

// NEW: PUT Update Expense
app.put('/expenses/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { id } = req.params;
  const { name, details, category, amount, date, account_id } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  const updates = [];
  const values = [];
  let paramIndex = 1;

  if (name !== undefined) { updates.push(`name = $${paramIndex++}`); values.push(name); }
  if (details !== undefined) { updates.push(`details = $${paramIndex++}`); values.push(details || null); }
  if (category !== undefined) { updates.push(`category = $${paramIndex++}`); values.push(category || null); }
  if (amount !== undefined) { updates.push(`amount = $${paramIndex++}`); values.push(amount); }
  if (date !== undefined) { updates.push(`date = $${paramIndex++}`); values.push(date); }
  if (account_id !== undefined) { updates.push(`account_id = $${paramIndex++}`); values.push(account_id); }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields provided for update.' });
  }

  values.push(id); // Add ID for WHERE clause
  values.push(user_id); // ADDED user_id for WHERE clause

  try {
    const result = await pool.query(
      `UPDATE expenses SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1} RETURNING *`, // ADDED user_id filter
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Expense not found or unauthorized' });
    }
    // Fetch with account_name for consistent response
    const fullExpense = await pool.query(`
      SELECT e.id, e.name, e.details, e.category, e.amount, e.date, e.account_id, acc.name AS account_name
      FROM expenses e
      JOIN accounts acc ON e.account_id = acc.id
      WHERE e.id = $1 AND e.user_id = $2 -- ADDED user_id filter
    `, [id, user_id]); // Use the ID from params directly

    res.json(fullExpense.rows[0]);
  } catch (error: unknown) {
    console.error('Error updating expense:', error);
    res.status(500).json({ error: 'Failed to update expense', detail: error instanceof Error ? error.message : String(error) });
  }
});

// NEW: DELETE Expense
app.delete('/expenses/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { id } = req.params;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    const result = await pool.query('DELETE FROM expenses WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Expense not found or unauthorized' });
    }
    res.json({ message: 'Expense deleted successfully' });
  } catch (error: unknown) {
    console.error('Error deleting expense:', error);
    res.status(500).json({ error: 'Failed to delete expense', detail: error instanceof Error ? error.message : String(error) });
  }
});

/* --- File upload & processing --- */
app.post('/transactions/upload', authMiddleware, upload.single('file'), async (req: Request, res: Response) => { // ADDED authMiddleware
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  if (!req.file) {
    return res.status(400).json({ detail: 'No file uploaded' });
  }
  // In a real application, you would save the file with a user_id association
  res.json({ message: 'File uploaded and processed (stub)', user_id: user_id }); // Include user_id for confirmation
});

/* --- Text description processing (UPDATED to use Gemini API) --- */
app.post('/transactions/process-text', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { description } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!description) {
    return res.status(400).json({ detail: 'Description is required' });
  }

  try {
    // Fetch all existing account names and categories to guide the LLM, filtered by user_id
    const accountsResult = await pool.query('SELECT name FROM accounts WHERE user_id = $1', [user_id]);
    const categoriesResult = await pool.query('SELECT DISTINCT category FROM transactions WHERE category IS NOT NULL AND user_id = $1', [user_id]);

    const accountNames = accountsResult.rows.map(row => row.name);
    const existingCategories = categoriesResult.rows.map(row => row.category);

    const prompt = `Extract transaction details from the following text.
    
    Text: "${description}"
    
    Rules for extraction:
    - Determine if the transaction is 'income' or 'expense'.
    - Extract the numerical 'amount'.
    - Extract the 'date' in YYYY-MM-DD format. If no year is specified, assume the current year (${new Date().getFullYear()}). If no day or month is specified, assume the current month and day.
    - Assign a relevant 'category' from the following list if applicable, otherwise suggest a new, concise, and appropriate accounting category: ${JSON.stringify(existingCategories)}. Common categories include: 'Sales Revenue', 'Fuel Expense', 'Salaries and Wages Expense', 'Rent Expense', 'Utilities Expense', 'Bank Charges & Fees', 'Interest Income', 'Projects Expenses', 'Accounting Fees Expense', 'Repairs & Maintenance Expense', 'Communication Expense', 'Miscellaneous Expense', 'Owner's Capital'.
    - Provide a concise 'description' of the transaction.
    - Identify the 'account' where the money moved (e.g., 'Bank', 'Cash'). If not explicitly mentioned, assume 'Bank'.
    
    Output the result as a JSON object with the following schema:
    `;

    const payload = {
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: {
          type: "OBJECT",
          properties: {
            type: { type: "STRING", enum: ["income", "expense"] },
            amount: { type: "NUMBER" },
            date: { type: "STRING", format: "date" },
            category: { type: "STRING" },
            description: { type: "STRING" },
            account: { type: "STRING" }
          },
          required: ["type", "amount", "date", "category", "description", "account"]
        }
      }
    };

    const apiKey = ""; // Canvas will provide this at runtime
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const llmResponse = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const result = await llmResponse.json();

    if (!result.candidates || result.candidates.length === 0 || !result.candidates[0].content || !result.candidates[0].content.parts || result.candidates[0].content.parts.length === 0) {
      throw new Error('LLM response structure is unexpected or content is missing.');
    }

    const extractedData = JSON.parse(result.candidates[0].content.parts[0].text);

    // Look up account_id based on the extracted account name, filtered by user_id
    const accountLookupResult = await pool.query('SELECT id FROM accounts WHERE name ILIKE $1 AND user_id = $2', [extractedData.account, user_id]);
    let account_id: number | null = null;

    if (accountLookupResult.rows.length > 0) {
      account_id = accountLookupResult.rows[0].id;
    } else {
      // If account not found, try to find a default 'Bank' account for this user
      const defaultBankResult = await pool.query('SELECT id FROM accounts WHERE name ILIKE $1 AND user_id = $2 LIMIT 1', ['%bank%', user_id]);
      if (defaultBankResult.rows.length > 0) {
        account_id = defaultBankResult.rows[0].id;
      } else {
        // Fallback if no 'Bank' account exists for this user, or handle as an error
        console.warn(`Account '${extractedData.account}' not found for user ${user_id}, and no default 'Bank' account. Transaction will be returned without account_id.`);
      }
    }

    // Prepare the response for the frontend
    res.json({
      type: extractedData.type,
      amount: extractedData.amount,
      date: extractedData.date,
      category: extractedData.category,
      description: extractedData.description,
      account_id: account_id, // Send the looked-up ID
      account_name: extractedData.account // Send the name for display
    });

  } catch (error: unknown) { // Changed 'err' to 'error: unknown'
    console.error('Error processing text with LLM:', error);
    res.status(500).json({ detail: 'Failed to process text description', error: error instanceof Error ? error.message : String(error) });
  }
});

/* --- Create a manual transaction (aligned to your DDL) --- */
// Create/Update manual transaction WITH auth + user_id scoping
app.post('/transactions/manual', authMiddleware, async (req: Request, res: Response) => {
  // company scope first, fallback to individual
  const user_id = (req.user!.parent_user_id || req.user!.user_id)!;

  // Accept both snake & camel from UI
  const {
    id,
    type,
    amount,
    description,
    date,
    category,
    account_id: account_id_raw,
    accountId,
    original_text,
    source,
    confirmed,
  } = req.body ?? {};

  const account_id = account_id_raw ?? accountId ?? null;

  // Minimal validation (keep your behaviour, just clearer messages)
  if (!type || !amount || !date) {
    return res.status(400).json({ detail: 'type, amount, and date are required' });
  }

  try {
    let result;

    if (id) {
      // UPDATE guarded by user_id so users can only update their own rows
      result = await pool.query(
        `
        UPDATE public.transactions
        SET
          "type"        = $1,
          amount        = $2::numeric(12,2),
          description   = $3,
          "date"        = $4::date,
          category      = $5,
          account_id    = $6,
          original_text = $7,
          "source"      = $8,
          confirmed     = COALESCE($9, confirmed)
        WHERE id = $10 AND user_id = $11
        RETURNING id, user_id, account_id, "type", amount, description, "date",
                  category, created_at, original_text, "source", confirmed
        `,
        [
          String(type),
          amount,
          description ?? null,
          date,
          category ?? null,
          account_id ?? null,
          original_text ?? null,
          (source ?? 'manual'),
          (typeof confirmed === 'boolean' ? confirmed : null),
          id,
          user_id,
        ]
      );

      if (result.rows.length === 0) {
        // Either not found or not owned by this user
        return res.status(404).json({ error: 'Transaction not found or not permitted' });
      }
    } else {
      // INSERT includes user_id to scope row ownership
      result = await pool.query(
        `
        INSERT INTO public.transactions
          (user_id, "type", amount, description, "date", category, account_id,
           original_text, "source", confirmed)
        VALUES
          ($1,      $2,     $3::numeric(12,2), $4,         $5::date, $6,       $7,
           $8,           $9,        COALESCE($10, true))
        RETURNING id, user_id, account_id, "type", amount, description, "date",
                  category, created_at, original_text, "source", confirmed
        `,
        [
          user_id,
          String(type),
          amount,
          description ?? null,
          date,
          category ?? null,
          account_id ?? null,
          original_text ?? null,
          (source ?? 'manual'),
          (typeof confirmed === 'boolean' ? confirmed : null),
        ]
      );
    }

    // Fetch with account_name for consistent response (also scoped by user_id)
    const full = await pool.query(
      `
      SELECT
        t.id,
        t.user_id,
        t.account_id,
        t."type",
        t.amount,
        t.description,
        t."date",
        t.category,
        t.created_at,
        t.original_text,
        t."source",
        t.confirmed,
        acc.name AS account_name
      FROM public.transactions t
      LEFT JOIN public.accounts acc ON t.account_id = acc.id
      WHERE t.id = $1 AND t.user_id = $2
      `,
      [result.rows[0].id, user_id]
    );

    if (full.rows.length === 0) {
      // Extremely unlikely, but handle
      return res.status(404).json({ error: 'Transaction not found after save' });
    }

    return res.json(full.rows[0]);
  } catch (error: any) {
    console.error('DB operation error:', error);
    return res.status(500).json({
      detail: 'Failed to perform transaction operation',
      error: error?.message || String(error),
    });
  }
});
// Simple ping route to keep service alive
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});


/* --- Audio upload & processing --- */
app.post('/transactions/process-audio', authMiddleware, upload.single('audio_file'), async (req: Request, res: Response) => { // ADDED authMiddleware
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  if (!req.file) {
    return res.status(400).json({ detail: 'No audio file uploaded' });
  }
  // In a real application, you would send the audio file to a speech-to-text service
  // and then send the transcribed text to the /transactions/process-text endpoint.
  // For now, we'll just return a stub message.
  res.json({ message: 'Audio uploaded and processed (stub)', user_id: user_id }); // Include user_id for confirmation
});

// POST Customer
app.post('/customers', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { name, contact_person, email, phone, address, tax_id } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!name) return res.status(400).json({ error: 'Customer name is required' });

  try {
    const result = await pool.query(
      `INSERT INTO customers (name, contact_person, email, phone, address, tax_id, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`, // ADDED user_id
      [name, contact_person || null, email || null, phone || null, address || null, tax_id || null, user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (error: unknown) { // Changed 'err' to 'error: unknown'
    console.error('Error adding customer:', error);
    res.status(500).json({ error: 'Failed to add customer', detail: error instanceof Error ? error.message : String(error) });
  }
});
/* --- Customer API Endpoints --- */

// GET All Customers (with optional search filter for the main table)
// GET All Customers (with optional search filter for the main table)
app.get('/api/customers', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const searchTerm = req.query.search as string | undefined;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    let query = `
        SELECT
            c.id,
            c.name,
            c.contact_person,
            c.email,
            c.phone,
            c.address,
            c.tax_id,
            COALESCE(SUM(i.total_amount), 0.00) AS total_invoiced /* Calculate total_invoiced */
        FROM
            public.customers c
        LEFT JOIN
            public.invoices i ON c.id = i.customer_id
        WHERE c.user_id = $1 -- ADDED user_id filter
    `;
    const queryParams: (string | number)[] = [user_id]; // Initialize with user_id
    let paramIndex = 2; // Start index at 2 because $1 is user_id

    if (searchTerm) {
        query += ` AND (LOWER(c.name) ILIKE $${paramIndex} OR LOWER(c.email) ILIKE $${paramIndex})`;
        queryParams.push(`%${searchTerm.toLowerCase()}%`);
    }

    query += `
        GROUP BY
            c.id, c.name, c.contact_person, c.email, c.phone, c.address, c.tax_id
        ORDER BY
            c.name ASC;
    `;

    try {
        // We use CustomerDB here because the query returns snake_case columns
        const { rows } = await pool.query<CustomerDB>(query, queryParams);
        const formattedRows = rows.map(mapCustomerToFrontend); // Map to frontend camelCase
        res.json(formattedRows);
    } catch (error: unknown) { // Explicitly type error as unknown
        console.error('Error fetching all customers:', error);
        res.status(500).json({ error: 'Failed to fetch customers', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Customers by Search Query (Still useful for specific search-as-you-type components if needed elsewhere)
app.get('/api/customers/search', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const query = req.query.query as string | undefined;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!query) {
        return res.status(400).json({ error: 'Search query is required' });
    }
    const searchTerm = `%${query.toLowerCase()}%`; // Already asserted as string or undefined above

    try {
        const result = await pool.query(
            `SELECT id, name FROM public.customers WHERE LOWER(name) LIKE $1 AND user_id = $2 ORDER BY name`, // ADDED user_id filter
            [searchTerm, user_id]
        );
        // Note: This returns only id and name, not full CustomerFrontend object
        res.json(result.rows.map(row => ({ id: row.id.toString(), name: row.name })));
    } catch (error: unknown) {
        console.error('Error searching customers:', error);
        res.status(500).json({ error: 'Failed to search customers', detail: error instanceof Error ? error.message : String(error) });
    }
});


// --- NEW ENDPOINT: Get Customers with Aggregated Sales Metrics for Clustering ---
// GET /api/customers/cluster-data
app.get('/api/customers/cluster-data', authMiddleware, async (req: Request, res: Response) => {
  // Use parent_user_id for company-level data access, fallback to user_id
  const user_id = req.user!.parent_user_id || req.user!.user_id;

  if (!user_id) {
    return res.status(400).json({ error: 'User ID is missing.' });
  }

  try {
    console.log(`[API /api/customers/cluster-data] Fetching clustered customer data for user_id: ${user_id}`);

    // --- Query Explanation ---
    // This query joins the customers table with an aggregation of sales data.
    // For each customer, it calculates:
    // - total_invoiced: Sum of all their sale total_amounts.
    // - number_of_purchases: Count of distinct sales records for them.
    // - average_order_value: total_invoiced / number_of_purchases (handled in JS for division by zero).
    // It uses a LEFT JOIN to include customers with zero sales.
    const result = await pool.query(`
      SELECT
        c.id AS customer_db_id, -- Original DB ID
        c.name,
        c.email,
        c.phone,
        c.address,
        c.tax_id,
        
        COALESCE(sales_summary.total_invoiced, 0) AS total_invoiced,
        COALESCE(sales_summary.number_of_purchases, 0) AS number_of_purchases
        -- average_order_value will be calculated in JS to avoid division by zero
      FROM public.customers c
      LEFT JOIN (
        SELECT
          s.customer_id,
          SUM(s.total_amount) AS total_invoiced,
          COUNT(s.id) AS number_of_purchases
          -- AVG(s.total_amount) could also be used, but manual calc is clearer
        FROM public.sales s
        WHERE s.user_id = $1
        GROUP BY s.customer_id
      ) AS sales_summary ON c.id = sales_summary.customer_id
      WHERE c.user_id = $1
      ORDER BY c.name;
    `, [user_id]);

    // --- Process Results ---
    const customersWithMetrics = result.rows.map(row => {
      const totalInvoiced = parseFloat(row.total_invoiced) || 0;
      const numberOfPurchases = parseInt(row.number_of_purchases, 10) || 0;
      const averageOrderValue = numberOfPurchases > 0 ? totalInvoiced / numberOfPurchases : 0;

      // Parse custom_fields if it exists on your customers table
      let parsedCustomFields = [];
      // if (row.custom_fields) {
      //   try {
      //     parsedCustomFields = JSON.parse(row.custom_fields);
      //   } catch (e) {
      //     console.error("Error parsing custom fields for customer", row.customer_db_id, e);
      //   }
      // }

      return {
        id: row.customer_db_id.toString(), // Convert DB ID to string for frontend consistency
        name: row.name,
        email: row.email,
        phone: row.phone,
        address: row.address,
        vatNumber: row.tax_id, // Map tax_id to vatNumber
        status: row.status || 'Active',
        totalInvoiced: parseFloat(totalInvoiced.toFixed(2)), // Ensure 2 decimals
        numberOfPurchases, // Integer
        averageOrderValue: parseFloat(averageOrderValue.toFixed(2)), // Ensure 2 decimals
        // customFields: parsedCustomFields // Uncomment if using custom fields
      };
    });

    console.log(`[API /api/customers/cluster-data] Successfully fetched data for ${customersWithMetrics.length} customers.`);
    res.status(200).json(customersWithMetrics);
  } catch (err: any) {
    console.error('[API /api/customers/cluster-data] Error fetching clustered customer data:', err);
    res.status(500).json({ error: 'Failed to fetch clustered customer data.', details: err.message });
  }
});
// --- END NEW ENDPOINT ---

// --- NEW ENDPOINT: Get Detailed Purchase History for a Single Customer ---
// GET /api/customers/:customerId/purchase-history
app.get('/api/customers/:customerId/purchase-history', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id || req.user!.user_id;
    const { customerId } = req.params;

    if (!user_id) {
        return res.status(400).json({ error: 'User ID is missing.' });
    }

    if (!customerId) {
        return res.status(400).json({ error: 'Customer ID is required.' });
    }

    // Validate if customerId is a number (assuming DB ID is an integer)
    const customerIdInt = parseInt(customerId, 10);
    if (isNaN(customerIdInt)) {
        return res.status(400).json({ error: 'Invalid Customer ID format.' });
    }

    try {
        console.log(`[API /api/customers/:customerId/purchase-history] Fetching history for customer ${customerIdInt}, user_id: ${user_id}`);

        // Fetch all sales for the customer
        const salesResult = await pool.query(`
            SELECT
                s.id AS sale_id,
                s.total_amount,
                s.payment_type,
                s.amount_paid,
                s.change_given,
                s.credit_amount,
                s.due_date,
                s.created_at AS sale_date,
                s.remaining_credit_amount
            FROM public.sales s
            WHERE s.user_id = $1 AND s.customer_id = $2
            ORDER BY s.created_at DESC;
        `, [user_id, customerIdInt]);

        const salesWithItems = await Promise.all(salesResult.rows.map(async (saleRow) => {
            // Fetch items for each sale
            const itemsResult = await pool.query(`
                SELECT
                    si.id AS item_id,
                    si.product_id,
                    si.product_name,
                    si.quantity,
                    si.unit_price_at_sale,
                    si.subtotal
                FROM public.sale_items si
                WHERE si.sale_id = $1 AND si.user_id = $2;
            `, [saleRow.sale_id, user_id]);

            return {
                id: saleRow.sale_id,
                totalAmount: parseFloat(saleRow.total_amount) || 0,
                paymentType: saleRow.payment_type,
                amountPaid: parseFloat(saleRow.amount_paid) || null,
                changeGiven: parseFloat(saleRow.change_given) || null,
                creditAmount: parseFloat(saleRow.credit_amount) || null,
                dueDate: saleRow.due_date ? new Date(saleRow.due_date).toISOString().split('T')[0] : null,
                saleDate: saleRow.sale_date ? new Date(saleRow.sale_date).toISOString() : null,
                remainingCreditAmount: parseFloat(saleRow.remaining_credit_amount) || null,
                items: itemsResult.rows.map(itemRow => ({
                    id: itemRow.item_id,
                    productId: itemRow.product_id,
                    productName: itemRow.product_name,
                    quantity: itemRow.quantity,
                    unitPriceAtSale: parseFloat(itemRow.unit_price_at_sale) || 0,
                    subtotal: parseFloat(itemRow.subtotal) || 0,
                }))
            };
        }));

        console.log(`[API /api/customers/:customerId/purchase-history] Successfully fetched history for customer ${customerIdInt}.`);
        res.status(200).json(salesWithItems);

    } catch (err: any) {
        console.error(`[API /api/customers/:customerId/purchase-history] Error fetching history for customer ${customerId}:`, err);
        res.status(500).json({ error: 'Failed to fetch customer purchase history.', details: err.message });
    }
});
// --- END NEW ENDPOINT ---
// GET Single Customer by ID
// Ensure this route is defined AFTER the /api/customers/cluster-data route
app.get('/api/customers/:id', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id;

    // --- ADD VALIDATION FOR ID ---
    const customerIdInt = parseInt(id, 10);
    if (isNaN(customerIdInt)) {
        console.error(`[API /api/customers/:id] Invalid Customer ID provided: ${id}`);
        return res.status(400).json({ error: 'Invalid Customer ID format.' });
    }
    // --- END ADD VALIDATION ---

    try {
        console.log(`[API /api/customers/:id] Fetching customer ${customerIdInt} for user_id: ${user_id}`);

        // --- UPDATE QUERY TO FETCH CORE CUSTOMER DATA ---
        // Note: This query fetches core customer details.
        // If you need aggregated sales data (like total_invoiced) for the single customer view,
        // you would need to join with sales or use a subquery, similar to the cluster-data endpoint.
        // For now, we fetch core data. Adjust if needed.
        const result = await pool.query<CustomerDB>(
            `SELECT
                c.id,
                c.name,
                c.contact_person,
                c.email,
                c.phone,
                c.address,
                c.tax_id,
                c.custom_fields,
                COALESCE(SUM(s.total_amount), 0) AS total_invoiced -- Example: Aggregate total invoiced
            FROM public.customers c
            LEFT JOIN public.sales s ON c.id = s.customer_id AND s.user_id = c.user_id -- Join sales for aggregation
            WHERE c.id = $1 AND c.user_id = $2
            GROUP BY c.id, c.name, c.contact_person, c.email, c.phone, c.address, c.tax_id, c.custom_fields`,
            [customerIdInt, user_id] // Use the validated integer ID
        );
        // --- END UPDATE QUERY ---

        if (result.rows.length === 0) {
            console.log(`[API /api/customers/:id] Customer ${customerIdInt} not found for user_id: ${user_id}`);
            return res.status(404).json({ error: 'Customer not found or unauthorized' });
        }

        // Assuming mapCustomerToFrontend can handle the structure returned by the query
        // Make sure mapCustomerToFrontend is defined elsewhere in your codebase
        const customerData = mapCustomerToFrontend(result.rows[0]);
        console.log(`[API /api/customers/:id] Successfully fetched customer ${customerIdInt}.`);
        res.json(customerData);
    } catch (error: unknown) {
        console.error(`[API /api/customers/:id] Error fetching customer ${id}:`, error);
        res.status(500).json({ error: 'Failed to fetch customer', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Create Customer
app.post('/api/customers', authMiddleware, async (req: Request, res: Response) => {
    // Destructure customFields from the request body
    const { name, contactPerson, email, phone, address, vatNumber, customFields }: CreateUpdateCustomerBody = req.body;
    const user_id = req.user!.parent_user_id;

    if (!name) {
        return res.status(400).json({ error: 'Customer name is required' });
    }

    try {
        const result = await pool.query<CustomerDB>(
            `INSERT INTO public.customers (name, contact_person, email, phone, address, tax_id, custom_fields, user_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [
                name,
                contactPerson || null,
                email || null,
                phone || null,
                address || null,
                vatNumber || null,
                // Add the customFields JSON data to the query parameters
                customFields || null,
                user_id
            ]
        );
        // The return type of this function needs to be a valid CustomerDB
        res.status(201).json(mapCustomerToFrontend(result.rows[0]));
    } catch (error: unknown) {
        console.error('Error adding customer:', error);
        res.status(500).json({ error: 'Failed to add customer', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT Update Customer
app.put('/api/customers/:id', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    // Destructure customFields from the request body
    const { name, contactPerson, email, phone, address, vatNumber, customFields }: CreateUpdateCustomerBody = req.body;
    const user_id = req.user!.parent_user_id;

    if (!name) {
        return res.status(400).json({ error: 'Customer name is required for update.' });
    }

    try {
        const result = await pool.query<CustomerDB>(
            `UPDATE public.customers
            SET name = $1, contact_person = $2, email = $3, phone = $4, address = $5, tax_id = $6, custom_fields = $7, updated_at = CURRENT_TIMESTAMP
            WHERE id = $8 AND user_id = $9 RETURNING *`, // Returning all fields
            [
                name,
                contactPerson || null,
                email || null,
                phone || null,
                address || null,
                vatNumber || null,
                // Add the customFields JSON data to the query parameters
                customFields || null,
                id,
                user_id
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Customer not found or unauthorized.' });
        }
        res.json(mapCustomerToFrontend(result.rows[0]));
    } catch (error: unknown) {
        console.error(`Error updating customer with ID ${id}:`, error);
        res.status(500).json({ error: 'Failed to update customer', detail: error instanceof Error ? error.message : String(error) });
    }
});

// DELETE Customer
app.delete('/api/customers/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    try {
        const { rowCount } = await pool.query(
            'DELETE FROM public.customers WHERE id = $1 AND user_id = $2', // ADDED user_id filter
            [id, user_id]
        );

        if (rowCount === 0) {
            return res.status(404).json({ error: 'Customer not found or unauthorized.' });
        }
        res.status(204).send(); // No Content for successful deletion
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error(`Error deleting customer with ID ${id}:`, error);
        if (error instanceof Error && 'code' in error && error.code === '23503') { // Foreign key violation (if customer is referenced)
            return res.status(409).json({
                error: 'Cannot delete customer: associated with existing invoices or other records.',
                detail: error.message
            });
        }
        res.status(500).json({ error: 'Failed to delete customer', detail: error instanceof Error ? error.message : String(error) });
    }
});
// GET Vendors
app.get('/vendors', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    const result = await pool.query('SELECT id, name, contact_person, email, phone, address, tax_id FROM vendors WHERE user_id = $1 ORDER BY name', [user_id]); // ADDED user_id filter
    res.json(result.rows);
  } catch (error: unknown) { // Changed 'err' to 'error: unknown'
    console.error('Error fetching vendors:', error);
    res.status(500).json({ error: 'Failed to fetch vendors', detail: error instanceof Error ? error.message : String(error) });
  }
});

// POST Vendor
app.post('/vendors', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { name, contact_person, email, phone, address, tax_id } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  if (!name) return res.status(400).json({ error: 'Vendor name is required' });

  try {
    const result = await pool.query(
      `INSERT INTO vendors (name, contact_person, email, phone, address, tax_id, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`, // ADDED user_id
      [name, contact_person || null, email || null, phone || null, address || null, tax_id || null, user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (error: unknown) { // Changed 'err' to 'error: unknown'
    console.error('Error adding vendor:', error);
    res.status(500).json({ error: 'Failed to add vendor', detail: error instanceof Error ? error.message : String(error) });
  }
});

// PUT Update Vendor
app.put('/vendors/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { id } = req.params;
  const { name, contact_person, email, phone, address, tax_id } = req.body;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!name) {
    return res.status(400).json({ error: 'Vendor name is required for update.' });
  }

  const updates = [];
  const values = [];
  let paramIndex = 1;

  if (name !== undefined) { updates.push(`name = $${paramIndex++}`); values.push(name); }
  if (contact_person !== undefined) { updates.push(`contact_person = $${paramIndex++}`); values.push(contact_person || null); }
  if (email !== undefined) { updates.push(`email = $${paramIndex++}`); values.push(email || null); }
  if (phone !== undefined) { updates.push(`phone = $${paramIndex++}`); values.push(phone || null); }
  if (address !== undefined) { updates.push(`address = $${paramIndex++}`); values.push(address || null); }
  if (tax_id !== undefined) { updates.push(`tax_id = $${paramIndex++}`); values.push(tax_id || null); }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields provided for update.' });
  }

  values.push(id); // Add ID for WHERE clause
  values.push(user_id); // ADDED user_id for WHERE clause

  try {
    const result = await pool.query(
      `UPDATE vendors SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1} RETURNING *`, // ADDED user_id filter
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Vendor not found or unauthorized' });
    }
    res.json(result.rows[0]);
  } catch (error: unknown) {
    console.error('Error updating vendor:', error);
    res.status(500).json({ error: 'Failed to update vendor', detail: error instanceof Error ? error.message : String(error) });
  }
});

// DELETE Vendor
app.delete('/vendors/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
  const { id } = req.params;
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    const result = await pool.query('DELETE FROM vendors WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Vendor not found or unauthorized' });
    }
    res.json({ message: 'Vendor deleted successfully' });
  } catch (error: unknown) {
    console.error('Error deleting vendor:', error);
    res.status(500).json({ error: 'Failed to delete vendor', detail: error instanceof Error ? error.message : String(error) });
  }
});


// Assuming 'app', 'authMiddleware', 'pool', 'Request', 'Response' are defined elsewhere


// GET Products/Services
app.get('/products-services', authMiddleware, async (req: Request, res: Response) => {
  // TypeScript now knows req.user might be undefined, so we add a check or use !
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  try {
    const result = await pool.query(
      'SELECT id, name, description, unit_price, cost_price, sku, is_service, max_quantity, min_quantity, stock_quantity, unit, available_value FROM products_services WHERE user_id = $1 ORDER BY name', // ADDED available_value to SELECT
      [user_id]
    );

    const formattedRows = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      unit_price: Number(row.unit_price),
      cost_price: row.cost_price ? Number(row.cost_price) : null,
      max_quantity: row.max_quantity ? Number(row.max_quantity) : null,
      min_quantity: row.min_quantity ? Number(row.min_quantity) : null,
      sku: row.sku,
      is_service: row.is_service,
      stock_quantity: Number(row.stock_quantity), // Changed to Number() to preserve decimals as per DDL
      created_at: row.created_at,
      updated_at: row.updated_at,
      tax_rate_id: row.tax_rate_id,
      category: row.category,
      unit: row.unit,
      available_value: row.available_value ? Number(row.available_value) : null, // Mapped available_value
    }));

    res.json(formattedRows);
  } catch (error) {
    console.error('Error fetching products/services:', error);
    res.status(500).json({ error: 'Failed to fetch products/services', detail: error instanceof Error ? error.message : String(error) });
  }
});

// POST Product/Service
app.post('/products-services', authMiddleware, async (req: Request, res: Response) => {
  const { name, description, unit_price, cost_price, sku, is_service, stock_quantity, max_quantity, min_quantity, available_value } = req.body; // Added available_value
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  if (!name || unit_price == null) {
    return res.status(400).json({ error: 'Product/Service name and unit_price are required' });
  }

  try {
    // Ensure the order of values matches the order of columns in the INSERT statement
    const result = await pool.query(
      `INSERT INTO products_services (name, description, unit_price, cost_price, sku, is_service, stock_quantity, min_quantity, max_quantity, available_value, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`, // Reordered columns for min/max and added available_value
      [
        name,
        description || null,
        unit_price,
        cost_price || null,
        sku || null,
        is_service || false,
        stock_quantity || 0, // This is for products
        min_quantity || null, // Corrected order
        max_quantity || null, // Corrected order
        available_value || null, // This is for services
        user_id
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding product/service:', error);
    res.status(500).json({ error: 'Failed to add product/service', detail: error instanceof Error ? error.message : String(error) });
  }
});

// PUT Update Product Stock (This route was already mostly correct for its specific purpose)
app.put('/products-services/:id/stock', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { adjustmentQuantity, updatedCostPrice } = req.body; // Added updatedCostPrice from frontend
  const user_id = req.user!.parent_user_id; // Get user_id from req.user

  const parsedAdjustmentQuantity = Number(adjustmentQuantity);
  const parsedUpdatedCostPrice = Number(updatedCostPrice); // Parse updatedCostPrice

  if (typeof parsedAdjustmentQuantity !== 'number' || isNaN(parsedAdjustmentQuantity)) {
    return res.status(400).json({ error: 'adjustmentQuantity must be a valid number.' });
  }

  try {
    await pool.query('BEGIN');

    const productResult = await pool.query(
      'SELECT stock_quantity, name FROM public.products_services WHERE id = $1 AND user_id = $2 FOR UPDATE',
      [id, user_id]
    );

    if (productResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Product or service not found or unauthorized.' });
    }

    const currentStock = Number(productResult.rows[0].stock_quantity);
    const productName = productResult.rows[0].name;

    const newStock = currentStock + parsedAdjustmentQuantity;

    if (parsedAdjustmentQuantity < 0 && newStock < 0) {
      await pool.query('ROLLBACK');
      return res.status(400).json({
        error: `Insufficient stock for "${productName}". Current stock: ${currentStock}. Cannot sell ${Math.abs(parsedAdjustmentQuantity)}.`,
        availableStock: currentStock,
      });
    }

    // Update stock quantity AND cost_price if provided
    const updateResult = await pool.query(
      `UPDATE public.products_services
       SET stock_quantity = $1, cost_price = COALESCE($2, cost_price), updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 AND user_id = $4
       RETURNING id, name, stock_quantity, cost_price`, // Return cost_price to confirm update
      [newStock, isNaN(parsedUpdatedCostPrice) ? null : parsedUpdatedCostPrice, id, user_id] // Use COALESCE to update cost_price only if a valid number is provided
    );

    await pool.query('COMMIT');

    res.json({
      message: `Stock for "${updateResult.rows[0].name}" updated successfully.`,
      product: updateResult.rows[0],
    });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error(`Error updating stock for product ID ${id}:`, error);
    res.status(500).json({
      error: 'Failed to update product stock',
      detail: error instanceof Error ? error.message : String(error)
    });
  }
});

// PUT Update Product/Service (General Update)
app.put('/products-services/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const user_id = req.user!.parent_user_id;
  const {
    name, description, unit_price, cost_price, sku,
    is_service, stock_quantity, unit, min_quantity, max_quantity, available_value // Added min_quantity, max_quantity, available_value
  } = req.body;

  try {
    const result = await pool.query(
      `UPDATE products_services
       SET name = $1, description = $2, unit_price = $3, cost_price = $4,
           sku = $5, is_service = $6, stock_quantity = $7, unit = $8,
           min_quantity = $9, max_quantity = $10, available_value = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 AND user_id = $13
       RETURNING *`, // Added min_quantity, max_quantity, available_value to SET clause
      [
        name,
        description || null,
        unit_price,
        cost_price || null,
        sku || null,
        is_service || false,
        stock_quantity || 0,
        unit || null,
        min_quantity || null, // Pass min_quantity
        max_quantity || null, // Pass max_quantity
        available_value || null, // Pass available_value
        id,
        user_id
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Product not found or unauthorized' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ error: 'Update failed', detail: error instanceof Error ? error.message : String(error) });
  }
});

// DELETE Product/Service (No changes needed, already correct)
app.delete('/products-services/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const user_id = req.user!.parent_user_id;

  try {
    const result = await pool.query(
      'DELETE FROM products_services WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, user_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Not found or unauthorized' });
    }

    res.json({ message: 'Deleted successfully', deleted: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete', detail: error instanceof Error ? error.message : String(error) });
  }
});


// =========================================================================
// 1. POST Create New Sale (app.post('/api/sales')) - Corrected
// =========================================================================


interface ProcessedCartItem {
    id: any; // Can be number or string (custom ID)
    name: string;
    quantity: number;
    unit_price: number;
    tax_rate_value: number;
    subtotal_excl_tax: number;
    tax_amount: number;
    subtotal_incl_tax: number;
    is_existing_product: boolean;
    cost_price: number | null;
    is_service: boolean; // Add this property to the type
}



// =========================================================================
// BEGIN: ENHANCED POST /api/sales
// =========================================================================
// =========================================================================
// 1. POST Create New Sale (app.post('/api/sales')) - with custom item fix
// =========================================================================
app.post('/api/sales', authMiddleware, async (req: Request, res: Response) => {
  const {
    cart,
    paymentType,
    total: frontendTotal, // Renamed for clarity
    customer,
    amountPaid: frontendAmountPaid, // Renamed for clarity
    change: frontendChange, // Renamed for clarity
    dueDate: frontendDueDate, // Renamed for clarity
    tellerName,
    branch,
    companyName
  } = req.body;
  const user_id = req.user!.parent_user_id;

  // --- 1. Validate Request Body ---
  if (!cart || !Array.isArray(cart) || cart.length === 0 || frontendTotal === undefined) {
    return res.status(400).json({ error: 'Cart cannot be empty and total amount is required.' });
  }

  if (paymentType === 'Credit' && (!customer || !customer.id)) {
    return res.status(400).json({ error: 'A customer is required for credit sales.' });
  }

  console.log(`[API /api/sales] Processing sale for user ${user_id}. Payment Type: ${paymentType}, Items: ${cart.length}`);

  const client = await pool.connect(); // Acquire a client for transaction

  try {
    // --- 2. Begin Database Transaction ---
    await client.query('BEGIN');

    let calculatedGrandTotal = 0;
    let calculatedTotalTax = 0;
    // Explicitly type the processedItems array
    const processedItems: ProcessedCartItem[] = []; // Now uses the new interface

    // --- 3. Process Each Cart Item ---
    for (const item of cart) {
      // Validate basic item structure
      if (item.quantity == null || item.unit_price == null || item.subtotal == null) {
        throw new Error(`Invalid cart item structure: ${JSON.stringify(item)}`);
      }
      const quantity = Number(item.quantity);
      const unitPrice = Number(item.unit_price);
      const itemSubtotal = Number(item.subtotal);
      const taxRateValue = Number(item.tax_rate_value ?? 0); // Default to 0 if not provided

      if (isNaN(quantity) || isNaN(unitPrice) || isNaN(itemSubtotal) || isNaN(taxRateValue) || quantity <= 0) {
        throw new Error(`Invalid numerical values in cart item: ${JSON.stringify(item)}`);
      }

      let itemId = item.id;
      let itemName = item.name;
      let isExistingProduct = typeof itemId === 'number'; // Heuristic: assume number IDs are existing DB records
      let costPrice = null; // Needed for COGS if using perpetual inventory
      let isService = item.is_service ?? false; // Get is_service from the incoming cart item

      // --- Handle Existing vs Custom Items ---
      if (isExistingProduct) {
        // --- 3a. Process Existing Product/Service ---
        console.log(`[API /api/sales] Processing existing item ID ${itemId}: ${itemName}, Qty: ${quantity}`);

        // Fetch current product details with a lock FOR UPDATE
        const productRes = await client.query(
          `SELECT id, name, stock_quantity, unit_price, cost_price, is_service
           FROM public.products_services
           WHERE id = $1 AND user_id = $2 FOR UPDATE`,
          [itemId, user_id]
        );

        if (productRes.rows.length === 0) {
          throw new Error(`Product or service with ID ${itemId} not found or unauthorized.`);
        }

        const dbProduct = productRes.rows[0];
        itemName = dbProduct.name; // Use name from DB for consistency
        costPrice = dbProduct.cost_price ? Number(dbProduct.cost_price) : null;
        isService = dbProduct.is_service; // Use the value from DB for existing products

        // *** MODIFICATION START ***
        // Always update stock quantity for existing items (products or services) if stock_quantity is not null
        const currentStock = Number(dbProduct.stock_quantity); // Assumes stock_quantity is always a number or 0 if null
        const newStock = currentStock - quantity; // Calculate new stock

        // Update stock regardless of initial value
        await client.query(
          `UPDATE public.products_services SET stock_quantity = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3`,
          [newStock, itemId, user_id]
        );
        console.log(`[API /api/sales] Updated stock for item ID ${itemId} (${itemName}). New stock: ${newStock}. Is Service: ${isService}`);

        if (newStock < 0) { // Log warning if stock goes negative, for both products and services
          console.warn(`[API /api/sales] Warning: Item ID ${itemId} (${itemName}) went into negative stock. New stock: ${newStock}. Is Service: ${isService}`);
        }
        // *** MODIFICATION END ***

        // Note: Item details like unit_price, tax_rate_value are taken from the *cart item* sent by frontend
        // This allows flexibility (e.g., temporary price changes), but ensure frontend sends correct data.
        // Backend recalculates subtotal below for verification.

      } else {
        // --- 3b. Process Custom Item ---
        console.log(`[API /api/sales] Processing custom item: ${itemName}, Qty: ${quantity}. Is Service: ${isService}`);
        // For custom items, we assume ID is a string like 'custom-...'
        // No stock update needed as they are either created new or are abstract.
        itemId = item.id; // Keep the custom ID string
        itemName = item.name;
        // costPrice remains null for custom items unless specified/logic added
        // isService is already pulled from item.is_service
      }

      // --- 3c. Recalculate & Validate Item Subtotal (Server-side calculation) ---
      const calculatedItemSubtotalExclTax = quantity * unitPrice;
      const calculatedItemTax = calculatedItemSubtotalExclTax * taxRateValue;
      const calculatedItemSubtotalInclTax = calculatedItemSubtotalExclTax + calculatedItemTax;

      // Optional: Add tolerance check instead of strict equality if minor rounding diffs are expected
      const tolerance = 0.01; // Adjust tolerance as needed
      if (Math.abs(calculatedItemSubtotalInclTax - itemSubtotal) > tolerance) {
        console.warn(`[API /api/sales] Subtotal mismatch for item ${itemName}. Frontend: ${itemSubtotal.toFixed(2)}, Calculated: ${calculatedItemSubtotalInclTax.toFixed(2)}. Using calculated value.`);
        // Optionally, you could throw an error here for stricter validation
        // throw new Error(`Subtotal mismatch for item ${itemName}. Please recalculate cart.`);
      }

      calculatedGrandTotal += calculatedItemSubtotalInclTax;
      calculatedTotalTax += calculatedItemTax;

      processedItems.push({
        id: itemId, // Number for DB items, string for custom
        name: itemName,
        quantity,
        unit_price: unitPrice,
        tax_rate_value: taxRateValue,
        subtotal_excl_tax: calculatedItemSubtotalExclTax,
        tax_amount: calculatedItemTax,
        subtotal_incl_tax: calculatedItemSubtotalInclTax,
        is_existing_product: isExistingProduct,
        cost_price: costPrice, // For potential COGS calc
        is_service: isService // Now correctly added to the processed item
      });
    }

    // --- 4. Validate Overall Total (Optional but recommended) ---
    const tolerance = 0.01;
    if (Math.abs(calculatedGrandTotal - Number(frontendTotal)) > tolerance) {
      console.warn(`[API /api/sales] Grand total mismatch. Frontend: ${Number(frontendTotal).toFixed(2)}, Calculated: ${calculatedGrandTotal.toFixed(2)}. Using calculated value.`);
      // Optionally, throw error for stricter validation
    }
    const finalGrandTotal = calculatedGrandTotal;
    const finalTotalTax = calculatedTotalTax;

    console.log(`[API /api/sales] Sale processed. Calculated Grand Total: ${finalGrandTotal.toFixed(2)}, Tax: ${finalTotalTax.toFixed(2)}`);

    // --- 5. Update Customer Balance Due for Credit Sales ---
    const remainingCreditAmount = paymentType === 'Credit' ? finalGrandTotal : null;
    const actualAmountPaid = paymentType !== 'Credit' ? Number(frontendAmountPaid) : null;
    const actualChangeGiven = paymentType === 'Cash' ? Number(frontendChange) : null;
    const actualDueDate = paymentType === 'Credit' ? frontendDueDate : null;

    if (paymentType === 'Credit' && customer?.id) {
      await client.query(
        `UPDATE public.customers
         SET balance_due = COALESCE(balance_due, 0) + $1, updated_at = CURRENT_TIMESTAMP
         WHERE id = $2 AND user_id = $3;`,
        [finalGrandTotal, customer.id, user_id]
      );
      console.log(`[API /api/sales] Updated customer ${customer.id} balance_due by ${finalGrandTotal.toFixed(2)}.`);
    }

    // --- 6. Insert Sale Record (Keep existing logic) ---
    const tellerId = req.user!.user_id; // Actual seller's user_id
    const customerId = customer?.id || null;
    const customerName = customer?.name || null;

    const salesInsertResult = await client.query(
      `INSERT INTO public.sales (
          customer_id, customer_name, total_amount, payment_type,
          amount_paid, change_given, remaining_credit_amount, due_date,
          teller_id, teller_name, branch, company_name, user_id
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING id, created_at;`,
      [
        customerId,
        customerName,
        finalGrandTotal, // Use calculated total
        paymentType,
        actualAmountPaid,
        actualChangeGiven,
        remainingCreditAmount,
        actualDueDate,
        tellerId,
        tellerName,
        branch,
        companyName,
        user_id
      ]
    );

    const saleId = salesInsertResult.rows[0].id;
    const saleTimestamp = salesInsertResult.rows[0].created_at;

    // --- 7. Insert Sale Items (Keep existing logic) ---
    for (const item of cart) {
      // Determine product name (use from item or fetch if needed for consistency, though item.name is usually fine)
      let productName = item.name;
      if (typeof item.id === 'number') {
        // (Optional) re-fetch to guarantee name; not required.
      }

      // ***** THE FIX: ensure product_id is an integer or NULL for custom items *****
      const productId =
        typeof item.id === 'number' && Number.isFinite(item.id) ? item.id : null;

      await client.query(
        `INSERT INTO public.sale_items (
           sale_id, product_id, product_name, quantity, unit_price_at_sale, subtotal, user_id
         ) VALUES ($1, $2, $3, $4, $5, $6, $7);`,
        [
          saleId,
          productId, // null for "custom-excel" etc
          productName,
          Number(item.quantity),
          Number(item.unit_price),
          Number(item.subtotal),
          user_id
        ]
      );
    }

    // --- 8. Determine Accounts and Amounts ---
    let accountIdDestination: number | null = null; // Account ID for payment received
    let amountReceived = 0;
    let transactionDescription = '';

    if (paymentType === 'Cash') {
      // Find Cash Account ID for this user
      const cashAccountRes = await client.query(
        `SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%cash%' AND type = 'Asset' LIMIT 1`,
        [user_id]
      );
      if (cashAccountRes.rows.length === 0) {
        throw new Error('Default Cash account not found for user.');
      }
      accountIdDestination = cashAccountRes.rows[0].id;
      amountReceived = Number(frontendAmountPaid) || 0; // Ensure it's a number
      transactionDescription = `Cash sale by ${tellerName || 'Unknown'} at ${branch || ''}`;

    } else if (paymentType === 'Bank') {
      // Find Bank Account ID (you might need a specific bank account selector in UI)
      const bankAccountRes = await client.query(
        `SELECT id FROM public.accounts WHERE user_id = $1 AND (name ILIKE '%bank%' OR name ILIKE '%cheque%') AND type = 'Asset' LIMIT 1`,
        [user_id]
      );
      if (bankAccountRes.rows.length === 0) {
        throw new Error('Default Bank account not found for user.');
      }
      accountIdDestination = bankAccountRes.rows[0].id;
      amountReceived = finalGrandTotal; // Full amount for bank/card
      transactionDescription = `Bank/Card sale by ${tellerName || 'Unknown'} at ${branch || ''}`;

    } else if (paymentType === 'Credit') {
      // Find Accounts Receivable ID
      const arAccountRes = await client.query(
        `SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%Accounts Receivable%' AND type = 'Asset' LIMIT 1`,
        [user_id]
      );
      if (arAccountRes.rows.length === 0) {
        throw new Error('Default Accounts Receivable account not found for user.');
      }
      accountIdDestination = arAccountRes.rows[0].id;
      amountReceived = finalGrandTotal; // Full amount owed
      transactionDescription = `Credit sale to ${customer?.name || 'Unknown Customer'}`;
    }

    // Find Sales Revenue Account ID
    const revenueAccountRes = await client.query(
      `SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%sales revenue%' AND type = 'Income' LIMIT 1`,
      [user_id]
    );
    if (revenueAccountRes.rows.length === 0) {
      throw new Error('Default Sales Revenue account not found for user.');
    }
    const accountIdRevenue = revenueAccountRes.rows[0].id;

    // Find VAT Payable Account ID (Assuming VAT is involved)
    const vatPayableAccountRes = await client.query(
      `SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%vat payable%' AND type = 'Liability' LIMIT 1`,
      [user_id]
    );
    // It's okay if VAT Payable account is not strictly required for all sales (e.g., zero-rated items)
    const accountIdVatPayable = vatPayableAccountRes.rows.length > 0 ? vatPayableAccountRes.rows[0].id : null;

    // --- 9. Record Financial Transactions ---
    const transactionDate = new Date(saleTimestamp).toISOString().split('T')[0]; // Use sale creation date
    const transactionCategory = 'Sales'; // Or 'POS Sales'

    // --- 9a. Debit: Payment Received (Cash/Bank/AR) ---
    if (amountReceived > 0 && accountIdDestination !== null) {
      await client.query(
        `INSERT INTO public.transactions (type, amount, description, date, category, account_id, source, confirmed, user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        ['Debit', amountReceived, `${transactionDescription} - Payment Received`, transactionDate, transactionCategory, accountIdDestination, 'POS', true, user_id]
      );
    }

    // --- 9b. Credit: Sales Revenue ---
    if (finalGrandTotal > 0) {
      await client.query(
        `INSERT INTO public.transactions (type, amount, description, date, category, account_id, source, confirmed, user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        ['Credit', finalGrandTotal, `${transactionDescription} - Sales Revenue`, transactionDate, transactionCategory, accountIdRevenue, 'POS', true, user_id]
      );
    }

    // --- 9c. Credit: VAT Payable (if applicable and tax collected > 0) ---
    if (accountIdVatPayable && finalTotalTax > 0) {
      await client.query(
        `INSERT INTO public.transactions (type, amount, description, date, category, account_id, source, confirmed, user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        ['Credit', finalTotalTax, `${transactionDescription} - VAT Collected`, transactionDate, transactionCategory, accountIdVatPayable, 'POS', true, user_id]
      );
    }

    // --- 9d. (Optional) Debit: Cost of Goods Sold & Credit: Inventory ---
    let totalCOGS = 0;
    for (const pItem of processedItems) {
      // Calculate COGS only for existing physical products (not services or custom items) that have a cost_price
      if (pItem.is_existing_product && pItem.cost_price !== null && !pItem.is_service) {
        const itemCOGS = pItem.quantity * pItem.cost_price;
        totalCOGS += itemCOGS;
      }
    }
    if (totalCOGS > 0) {
      // Find COGS and Inventory Account IDs
      const cogsAccountRes = await client.query(`SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%cost of goods sold%' AND type = 'Expense' LIMIT 1`, [user_id]);
      const inventoryAccountRes = await client.query(`SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%inventory%' AND type = 'Asset' LIMIT 1`, [user_id]);
      const accountIdCOGS = cogsAccountRes.rows[0]?.id;
      const accountIdInventory = inventoryAccountRes.rows[0]?.id;

      if (accountIdCOGS && accountIdInventory) {
        await client.query(
          `INSERT INTO public.transactions (type, amount, description, date, category, account_id, source, confirmed, user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          ['Debit', totalCOGS, `COGS for sale ID ${saleId}`, transactionDate, 'COGS', accountIdCOGS, 'POS', true, user_id]
        );
        await client.query(
          `INSERT INTO public.transactions (type, amount, description, date, category, account_id, source, confirmed, user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          ['Credit', totalCOGS, `Inventory reduction for sale ID ${saleId}`, transactionDate, 'Inventory', accountIdInventory, 'POS', true, user_id]
        );
      }
    }

    // --- 10. Commit Transaction ---
    await client.query('COMMIT');
    console.log(`[API /api/sales] Sale committed successfully for user ${user_id}.`);

    // --- 11. Respond Success ---
    res.status(201).json({
      message: 'Sale submitted successfully and transactions recorded!',
      saleId: saleId,
      timestamp: saleTimestamp,
    });

  } catch (error) {
    // --- Rollback on any error ---
    await client.query('ROLLBACK');
    console.error('[API /api/sales] Error processing sale:', error);
    // Send a user-friendly error message
    res.status(500).json({
      error: 'Failed to process sale.',
      detail: error instanceof Error ? error.message : String(error)
    });
  } finally {
    // --- Release the client back to the pool ---
    client.release();
  }
});

// =========================================================================
// END: ENHANCED POST /api/sales
// =========================================================================

// ... (rest of your existing endpoints) ...


// =========================================================================
// 2. GET Outstanding Credit Sales (app.get('/api/credit-sales'))
// This is the fixed endpoint from our previous step.
// =========================================================================
app.get('/api/credit-sales', authMiddleware, async (req: Request, res: Response) => {
    if (!req.user || !req.user.user_id) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const user_id = req.user.user_id;
    console.log(`Fetching outstanding credit sales for user_id: ${user_id}`);

    try {
        const result = await pool.query(
            `SELECT
              s.id,
              s.customer_id,
              c.name AS customer_name,
              s.created_at AS sale_date,
              s.total_amount,
              s.remaining_credit_amount,
              s.payment_type AS payment_method,
              s.due_date
            FROM public.sales s
            LEFT JOIN public.customers c ON s.customer_id = c.id
            WHERE s.user_id = $1
              AND s.payment_type = 'Credit'
              AND s.remaining_credit_amount > 0
            ORDER BY s.created_at DESC;`,
            [user_id]
        );

        const creditSales = result.rows.map(row => ({
            ...row,
            total_amount: parseFloat(row.total_amount),
            remaining_credit_amount: parseFloat(row.remaining_credit_amount),
        }));

        console.log('Backend API: Successfully fetched outstanding credit sales.', creditSales);
        res.status(200).json(creditSales);

    } catch (error) {
        console.error('Error fetching outstanding credit sales:', error);
        res.status(500).json({ error: 'Failed to fetch outstanding credit sales.' });
    }
});


// =========================================================================
// 3. GET Credit History for Customer (app.get('/api/sales/customer/:customerId/credit-history'))
// --- FIX APPLIED HERE: Explicitly parse numeric values. ---
// =========================================================================
app.get('/api/sales/customer/:customerId/credit-history', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    const { customerId } = req.params;

    try {
        const result = await pool.query(
            `SELECT
              s.id,
              s.customer_id,
              s.customer_name,
              s.created_at AS sale_date,
              s.total_amount,
              s.remaining_credit_amount,
              s.payment_type AS payment_method,
              s.due_date
            FROM public.sales s
            WHERE s.user_id = $1 AND s.customer_id = $2 AND s.payment_type = 'Credit'
            ORDER BY s.created_at DESC;`,
            [user_id, customerId]
        );

        // --- FIX: Explicitly parse numeric values before sending to the client ---
        const creditHistory = result.rows.map(row => ({
            ...row,
            total_amount: parseFloat(row.total_amount),
            remaining_credit_amount: parseFloat(row.remaining_credit_amount),
        }));

        res.status(200).json(creditHistory);
    } catch (error) {
        console.error(`Error fetching credit history for customer ${customerId}:`, error);
        res.status(500).json({ error: 'Failed to fetch customer credit history.' });
    }
});


// =========================================================================
// 4. POST Credit Payments (app.post('/api/credit-payments'))
// This endpoint is unchanged from our previous discussion.
// =========================================================================
app.post('/api/credit-payments', authMiddleware, async (req: Request, res: Response) => {
    const { customerId, saleId, amountPaid, paymentMethod, description, recordedBy } = req.body;
    const user_id = req.user!.parent_user_id;

    if (!customerId || !amountPaid || Number(amountPaid) <= 0) {
        return res.status(400).json({ error: 'Customer ID and a positive amount paid are required.' });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        await client.query(
            `INSERT INTO public.credit_payments (
                user_id, customer_id, sale_id, amount_paid, payment_method, description, recorded_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7);`,
            [user_id, customerId, saleId, Number(amountPaid), paymentMethod, description, recordedBy]
        );

        await client.query(
            `UPDATE public.customers
             SET balance_due = balance_due - $1
             WHERE id = $2 AND user_id = $3;`,
            [Number(amountPaid), customerId, user_id]
        );

        if (saleId) {
            const updateSaleQuery = `
                UPDATE public.sales
                SET remaining_credit_amount = remaining_credit_amount - $1
                WHERE id = $2 AND user_id = $3;
            `;
            await client.query(updateSaleQuery, [Number(amountPaid), saleId, user_id]);
        }

        await client.query('COMMIT');
        res.status(200).json({ message: 'Credit payment recorded successfully.' });

    } catch (error: unknown) {
        await client.query('ROLLBACK');
        console.error('Error recording credit payment:', error);
        res.status(500).json({
            error: 'Failed to record credit payment',
            detail: error instanceof Error ? error.message : String(error)
        });
    } finally {
        client.release();
    }
});

// =========================================================================
// 3. GET Sales Data for Dashboard (app.get('/api/dashboard/sales')) - Your existing code
// =========================================================================
app.get('/api/dashboard/sales', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;

    try {
        const salesDataResult = await pool.query(
            `SELECT
                s.id AS sale_id,
                s.created_at AS sale_date,
                si.product_id,
                si.product_name,
                si.quantity,
                si.unit_price_at_sale
            FROM
                public.sales s
            JOIN
                public.sale_items si ON s.id = si.sale_id
            WHERE
                s.user_id = $1
            ORDER BY
                s.created_at ASC;`,
            [user_id]
        );

        const processedSales = salesDataResult.rows.map(row => ({
            saleId: row.sale_id,
            createdAt: new Date(row.sale_date),
            product_id: row.product_id,
            product_name: row.product_name,
            quantity: Number(row.quantity),
            unit_price_at_sale: Number(row.unit_price_at_sale)
        }));

        res.status(200).json(processedSales);

    } catch (error: unknown) {
        console.error('Error fetching dashboard sales data:', error);
        res.status(500).json({
            error: 'Failed to fetch dashboard sales data',
            detail: error instanceof Error ? error.message : String(error)
        });
    }
});

/* --- Invoice API Endpoints --- */

// GET All Invoices (List View)
app.get('/api/invoices', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query(`
            SELECT
                i.id,
                i.invoice_number,
                i.invoice_date,
                i.due_date,
                i.total_amount,
                i.status,
                i.currency,
                c.name AS customer_name,
                c.id AS customer_id
            FROM public.invoices i
            LEFT JOIN public.customers c ON i.customer_id = c.id
            WHERE i.user_id = $1 -- ADDED user_id filter
            ORDER BY i.invoice_date DESC, i.invoice_number DESC
        `, [user_id]);
        res.json(result.rows);
    } catch (error: unknown) {
        console.error('Error fetching invoices:', error);
        res.status(500).json({ error: 'Failed to fetch invoices', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Single Invoice with Line Items
app.get('/api/invoices/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const invoiceResult = await pool.query(`
            SELECT
                i.id,
                i.invoice_number,
                i.customer_id,
                c.name AS customer_name,
                c.email AS customer_email,
                c.phone AS customer_phone,
                c.address AS customer_address,
                i.invoice_date,
                i.due_date,
                i.total_amount,
                i.status,
                i.currency,
                i.notes,
                i.created_at,
                i.updated_at
            FROM public.invoices i
            LEFT JOIN public.customers c ON i.customer_id = c.id
            WHERE i.id = $1 AND i.user_id = $2 -- ADDED user_id filter
        `, [id, user_id]);

        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found or unauthorized' });
        }

        const lineItemsResult = await pool.query(`
            SELECT
                ili.id,
                ili.product_service_id,
                ps.name AS product_service_name,
                ili.description,
                ili.quantity,
                ili.unit_price,
                ili.line_total,
                ili.tax_rate
            FROM public.invoice_line_items ili
            LEFT JOIN public.products_services ps ON ili.product_service_id = ps.id
            WHERE ili.invoice_id = $1
            ORDER BY ili.id
        `, [id]);

        const invoice = invoiceResult.rows[0];
        invoice.line_items = lineItemsResult.rows;

        res.json(invoice);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching invoice:', error);
        res.status(500).json({ error: 'Failed to fetch invoice', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Create Invoice
app.post('/api/invoices', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { invoice_number, customer_id, customer_name, invoice_date, due_date, total_amount, status, currency, notes, line_items } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!invoice_number || !invoice_date || !due_date || total_amount == null || !line_items || line_items.length === 0) {
        return res.status(400).json({ error: 'Missing required invoice fields or line items' });
    }

    if (!customer_id && (!customer_name || customer_name.trim() === '')) {
        return res.status(400).json({ error: 'Customer ID or Customer Name is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let finalCustomerId = customer_id;

        if (!finalCustomerId) {
            const existingCustomerResult = await client.query('SELECT id FROM public.customers WHERE LOWER(name) = LOWER($1) AND user_id = $2', [customer_name.trim(), user_id]); // ADDED user_id filter

            if (existingCustomerResult.rows.length > 0) {
                finalCustomerId = existingCustomerResult.rows[0].id;
            } else {
                const newCustomerResult = await client.query(
                    `INSERT INTO public.customers (name, total_invoiced, user_id) VALUES ($1, 0.00, $2) RETURNING id`, // ADDED user_id
                    [customer_name.trim(), user_id]
                );
                finalCustomerId = newCustomerResult.rows[0].id;
            }
        }

        const invoiceResult = await client.query(
            `INSERT INTO public.invoices (invoice_number, customer_id, invoice_date, due_date, total_amount, status, currency, notes, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`, // ADDED user_id
            [invoice_number, finalCustomerId, invoice_date, due_date, total_amount, status || 'Draft', currency || 'ZAR', notes || null, user_id]
        );
        const invoiceId = invoiceResult.rows[0].id;

        for (const item of line_items) {
            if (!item.description || item.quantity == null || item.unit_price == null || item.line_total == null) {
                throw new Error('Missing required line item fields');
            }
            await client.query(
                `INSERT INTO public.invoice_line_items (invoice_id, product_service_id, description, quantity, unit_price, line_total, tax_rate)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [invoiceId, item.product_service_id || null, item.description, item.quantity, item.unit_price, item.line_total, item.tax_rate || 0.00]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ id: invoiceId, message: 'Invoice created successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error creating invoice:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'Invoice number already exists.' });
        }
        res.status(500).json({ error: 'Failed to create invoice', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// PUT Update Invoice
app.put('/api/invoices/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const { invoice_number, customer_id, customer_name, invoice_date, due_date, total_amount, status, currency, notes, line_items } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!invoice_number || !invoice_date || !due_date || total_amount == null || !line_items) {
        return res.status(400).json({ error: 'Missing required invoice fields or line items' });
    }

    if (!customer_id && (!customer_name || customer_name.trim() === '')) {
        return res.status(400).json({ error: 'Customer ID or Customer Name is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let finalCustomerId = customer_id;

        if (!finalCustomerId) {
            const existingCustomerResult = await client.query('SELECT id FROM public.customers WHERE LOWER(name) = LOWER($1) AND user_id = $2', [customer_name.trim(), user_id]); // ADDED user_id filter

            if (existingCustomerResult.rows.length > 0) {
                finalCustomerId = existingCustomerResult.rows[0].id;
            } else {
                const newCustomerResult = await client.query(
                    `INSERT INTO public.customers (name, total_invoiced, user_id) VALUES ($1, 0.00, $2) RETURNING id`, // ADDED user_id
                    [customer_name.trim(), user_id]
                );
                finalCustomerId = newCustomerResult.rows[0].id;
            }
        }

        const updateInvoiceResult = await client.query(
            `UPDATE public.invoices
             SET
               invoice_number = $1,
               customer_id = $2,
               invoice_date = $3,
               due_date = $4,
               total_amount = $5,
               status = $6,
               currency = $7,
               notes = $8,
               updated_at = CURRENT_TIMESTAMP
             WHERE id = $9 AND user_id = $10 RETURNING id`, // ADDED user_id filter
            [invoice_number, finalCustomerId, invoice_date, due_date, total_amount, status, currency || 'ZAR', notes || null, id, user_id]
        );

        if (updateInvoiceResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Invoice not found for update or unauthorized' });
        }

        await client.query('DELETE FROM public.invoice_line_items WHERE invoice_id = $1', [id]);

        for (const item of line_items) {
            if (!item.description || item.quantity == null || item.unit_price == null || item.line_total == null) {
                throw new Error('Missing required line item fields');
            }
            await client.query(
                `INSERT INTO public.invoice_line_items (invoice_id, product_service_id, description, quantity, unit_price, line_total, tax_rate)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [id, item.product_service_id || null, item.description, item.quantity, item.unit_price, item.line_total, item.tax_rate || 0.00]
            );
        }

        await client.query('COMMIT');
        res.json({ id: id, message: 'Invoice updated successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error updating invoice:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'Invoice number already exists.' });
        }
        res.status(500).json({ error: 'Failed to update invoice', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// DELETE Invoice
app.delete('/api/invoices/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query('DELETE FROM public.invoices WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found or unauthorized' });
        }
        res.json({ message: 'Invoice deleted successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error deleting invoice:', error);
        res.status(500).json({ error: 'Failed to delete invoice', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Record Invoice Payment
app.post('/api/invoices/:id/payment', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params; // Invoice ID
    const { amount_paid, payment_date, notes, account_id, transaction_description, transaction_category } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (amount_paid == null || !payment_date || !account_id) {
        return res.status(400).json({ error: 'Amount paid, payment date, and account ID are required' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Check if the invoice belongs to the user
        const invoiceCheck = await client.query('SELECT id FROM public.invoices WHERE id = $1 AND user_id = $2', [id, user_id]);
        if (invoiceCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Invoice not found or unauthorized.' });
        }

        const transactionResult = await client.query(
            `INSERT INTO public.transactions (type, amount, description, date, category, account_id, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, // ADDED user_id
            ['income', amount_paid, transaction_description || `Payment for Invoice ${id}`, payment_date, transaction_category || 'Trading Income', account_id, user_id]
        );
        const transactionId = transactionResult.rows[0].id;

        await client.query(
            `INSERT INTO public.invoice_payments (invoice_id, transaction_id, amount_paid, payment_date, notes, user_id)
             VALUES ($1, $2, $3, $4, $5, $6)`, // ADDED user_id
            [id, transactionId, amount_paid, payment_date, notes || null, user_id]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'Invoice payment recorded successfully', transaction_id: transactionId });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error recording invoice payment:', error);
        res.status(500).json({ error: 'Failed to record invoice payment', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

/* --- Quotations API Endpoints --- */

// GET All Quotations (List View)
app.get('/api/quotations', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query(`
            SELECT
                q.id,
                q.quotation_number,
                q.quotation_date,
                q.expiry_date,
                q.total_amount,
                q.status,
                q.currency,
                c.name AS customer_name,
                c.id AS customer_id
            FROM public.quotations q
            JOIN public.customers c ON q.customer_id = c.id
            WHERE q.user_id = $1 -- ADDED user_id filter
            ORDER BY q.quotation_date DESC, q.quotation_number DESC
        `, [user_id]);
        res.json(result.rows);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching quotations:', error);
        res.status(500).json({ error: 'Failed to fetch quotations', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Single Quotation with Line Items
app.get('/api/quotations/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const quotationResult = await pool.query(`
            SELECT
                q.id,
                q.quotation_number,
                q.customer_id,
                c.name AS customer_name,
                c.email AS customer_email,
                c.phone AS customer_phone,
                c.address AS customer_address,
                q.quotation_date,
                q.expiry_date,
                q.total_amount,
                q.status,
                q.currency,
                q.notes,
                q.created_at,
                q.updated_at
            FROM public.quotations q
            JOIN public.customers c ON q.customer_id = c.id
            WHERE q.id = $1 AND q.user_id = $2 -- ADDED user_id filter
        `, [id, user_id]);

        if (quotationResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quotation not found or unauthorized' });
        }

        const lineItemsResult = await pool.query(`
            SELECT
                qli.id,
                qli.product_service_id,
                ps.name AS product_service_name,
                qli.description,
                qli.quantity,
                qli.unit_price,
                qli.line_total,
                qli.tax_rate
            FROM public.quotation_line_items qli
            LEFT JOIN public.products_services ps ON qli.product_service_id = ps.id
            WHERE qli.quotation_id = $1
            ORDER BY qli.id
        `, [id]);

        const quotation = quotationResult.rows[0];
        quotation.line_items = lineItemsResult.rows;

        res.json(quotation);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching quotation:', error);
        res.status(500).json({ error: 'Failed to fetch quotation', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Create Quotation
app.post('/api/quotations', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { quotation_number, customer_id, customer_name, quotation_date, expiry_date, total_amount, status, currency, notes, line_items } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!quotation_number || !quotation_date || total_amount == null || !line_items || line_items.length === 0) {
        return res.status(400).json({ error: 'Missing required quotation fields or line items' });
    }

    // Validate customer: either customer_id or customer_name must be present
    if (!customer_id && (!customer_name || customer_name.trim() === '')) {
        return res.status(400).json({ error: 'Customer ID or Customer Name is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let finalCustomerId = customer_id;

        // If customer_id is NOT provided, it means we need to create a new customer
        if (!finalCustomerId) {
            // Check if a customer with this name already exists to prevent duplicates, filtered by user_id
            const existingCustomerResult = await client.query('SELECT id FROM public.customers WHERE LOWER(name) = LOWER($1) AND user_id = $2', [customer_name.trim(), user_id]); // ADDED user_id filter

            if (existingCustomerResult.rows.length > 0) {
                // If customer exists, use their ID
                finalCustomerId = existingCustomerResult.rows[0].id;
            } else {
                // Otherwise, create a new customer, associating with user_id
                const newCustomerResult = await client.query(
                    `INSERT INTO public.customers (name, total_invoiced, user_id) VALUES ($1, 0.00, $2) RETURNING id`, // ADDED user_id
                    [customer_name.trim(), user_id]
                );
                finalCustomerId = newCustomerResult.rows[0].id;
            }
        }

        const quotationResult = await client.query(
            `INSERT INTO public.quotations (quotation_number, customer_id, quotation_date, expiry_date, total_amount, status, currency, notes, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`, // ADDED user_id
            [quotation_number, finalCustomerId, quotation_date, expiry_date || null, total_amount, status || 'Draft', currency || 'ZAR', notes || null, user_id]
        );
        const quotationId = quotationResult.rows[0].id;

        for (const item of line_items) {
            if (!item.description || item.quantity == null || item.unit_price == null || item.line_total == null) {
                throw new Error('Missing required line item fields');
            }
            await client.query(
                `INSERT INTO public.quotation_line_items (quotation_id, product_service_id, description, quantity, unit_price, line_total, tax_rate)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [quotationId, item.product_service_id || null, item.description, item.quantity, item.unit_price, item.line_total, item.tax_rate || 0.00]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ id: quotationId, message: 'Quotation created successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error creating quotation:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'Quotation number already exists.' });
        }
        res.status(500).json({ error: 'Failed to create quotation', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// PUT Update Quotation
app.put('/api/quotations/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params; // Correctly extract 'id' from params
    const { quotation_number, customer_id, customer_name, quotation_date, expiry_date, total_amount, status, currency, notes, line_items } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!quotation_number || !quotation_date || total_amount == null || !line_items) {
        return res.status(400).json({ error: 'Missing required quotation fields or line items' });
    }

    // Validate customer: either customer_id or customer_name must be present
    if (!customer_id && (!customer_name || customer_name.trim() === '')) {
        return res.status(400).json({ error: 'Customer ID or Customer Name is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let finalCustomerId = customer_id;

        if (!finalCustomerId) {
            const existingCustomerResult = await client.query('SELECT id FROM public.customers WHERE LOWER(name) = LOWER($1) AND user_id = $2', [customer_name.trim(), user_id]); // ADDED user_id filter

            if (existingCustomerResult.rows.length > 0) {
                finalCustomerId = existingCustomerResult.rows[0].id;
            } else {
                const newCustomerResult = await client.query(
                    `INSERT INTO public.customers (name, total_invoiced, user_id) VALUES ($1, 0.00, $2) RETURNING id`, // ADDED user_id
                    [customer_name.trim(), user_id]
                );
                finalCustomerId = newCustomerResult.rows[0].id;
            }
        }

        const updateQuotationResult = await client.query(
            `UPDATE public.quotations
             SET
               quotation_number = $1,
               customer_id = $2,
               quotation_date = $3,
               expiry_date = $4,
               total_amount = $5,
               status = $6,
               currency = $7,
               notes = $8,
               updated_at = CURRENT_TIMESTAMP
             WHERE id = $9 AND user_id = $10 RETURNING id`, // ADDED user_id filter
            [quotation_number, finalCustomerId, quotation_date, expiry_date || null, total_amount, status, currency || 'ZAR', notes || null, id, user_id]
        );

        if (updateQuotationResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Quotation not found for update or unauthorized' });
        }

        await client.query('DELETE FROM public.quotation_line_items WHERE quotation_id = $1', [id]);

        for (const item of line_items) {
            if (!item.description || item.quantity == null || item.unit_price == null || item.line_total == null) {
                throw new Error('Missing required line item fields');
            }
            await client.query(
                `INSERT INTO public.quotation_line_items (quotation_id, product_service_id, description, quantity, unit_price, line_total, tax_rate)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [id, item.product_service_id || null, item.description, item.quantity, item.unit_price, item.line_total, item.tax_rate || 0.00] // Use 'id' here
            );
        }

        await client.query('COMMIT');
        res.json({ id: id, message: 'Quotation updated successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error updating quotation:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'Quotation number already exists.' });
        }
        res.status(500).json({ error: 'Failed to update quotation', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// DELETE Quotation
app.delete('/api/quotations/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query('DELETE FROM public.quotations WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Quotation not found or unauthorized' });
        }
        res.json({ message: 'Quotation deleted successfully' });
    }
    catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error deleting quotation:', error);
        res.status(500).json({ error: 'Failed to delete quotation', detail: error instanceof Error ? error.message : String(error) });
    }
});


/* --- Purchases API Endpoints --- */

// GET All Purchases (List View)
app.get('/api/purchases', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query(`
            SELECT
                p.id,
                p.po_number,
                p.order_date,
                p.delivery_date,
                p.total_amount,
                p.status,
                p.currency,
                v.name AS vendor_name,
                v.id AS vendor_id
            FROM public.purchases p
            JOIN public.vendors v ON p.vendor_id = v.id
            WHERE p.user_id = $1 -- ADDED user_id filter
            ORDER BY p.order_date DESC, p.po_number DESC
        `, [user_id]);
        res.json(result.rows);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching purchases:', error);
        res.status(500).json({ error: 'Failed to fetch purchases', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Single Purchase with Line Items
app.get('/api/purchases/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const purchaseResult = await pool.query(`
            SELECT
                p.id,
                p.po_number,
                p.vendor_id,
                v.name AS vendor_name,
                v.email AS vendor_email,
                v.phone AS vendor_phone,
                v.address AS vendor_address,
                p.order_date,
                p.delivery_date,
                p.total_amount,
                p.status,
                p.currency,
                p.notes,
                p.created_at,
                p.updated_at
            FROM public.purchases p
            JOIN public.vendors v ON p.vendor_id = v.id
            WHERE p.id = $1 AND p.user_id = $2 -- ADDED user_id filter
        `, [id, user_id]);

        if (purchaseResult.rows.length === 0) {
            return res.status(404).json({ error: 'Purchase not found or unauthorized' });
        }

        const lineItemsResult = await pool.query(`
            SELECT
                pli.id,
                pli.product_service_id,
                ps.name AS product_service_name,
                pli.description,
                pli.quantity,
                pli.unit_cost,
                pli.line_total,
                pli.tax_rate
            FROM public.purchase_line_items pli
            LEFT JOIN public.products_services ps ON pli.product_service_id = ps.id
            WHERE pli.purchase_id = $1
            ORDER BY pli.id
        `, [id]);

        const purchase = purchaseResult.rows[0];
        purchase.line_items = lineItemsResult.rows;

        res.json(purchase);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching purchase:', error);
        res.status(500).json({ error: 'Failed to fetch purchase', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Create Purchase
app.post('/api/purchases', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    // Destructure vendor_name (manual input) from req.body
    const { po_number, vendor_id, vendor_name, order_date, delivery_date, total_amount, status, currency, notes, line_items } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!order_date || total_amount == null || !line_items || line_items.length === 0) {
        return res.status(400).json({ error: 'Missing required purchase fields or line items' });
    }

    // Validate vendor: either vendor_id or vendor_name must be present
    if (!vendor_id && (!vendor_name || vendor_name.trim() === '')) {
        return res.status(400).json({ error: 'Vendor ID or Vendor Name is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let finalVendorId = vendor_id;

        // If vendor_id is NOT provided, it means we need to create a new vendor
        if (!finalVendorId) {
            // Check if a vendor with this name already exists to prevent duplicates, filtered by user_id
            const existingVendorResult = await pool.query('SELECT id FROM public.vendors WHERE LOWER(name) = LOWER($1) AND user_id = $2', [vendor_name.trim(), user_id]); // ADDED user_id filter

            if (existingVendorResult.rows.length > 0) {
                // If vendor exists, use their ID
                finalVendorId = existingVendorResult.rows[0].id;
            } else {
                // Otherwise, create a new vendor, associating with user_id
                const newVendorResult = await pool.query(
                    `INSERT INTO public.vendors (name, user_id) VALUES ($1, $2) RETURNING id`, // ADDED user_id
                    [vendor_name.trim(), user_id]
                );
                finalVendorId = newVendorResult.rows[0].id;
            }
        }

        const purchaseResult = await client.query(
            `INSERT INTO public.purchases (po_number, vendor_id, order_date, delivery_date, total_amount, status, currency, notes, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`, // ADDED user_id
            [po_number || null, finalVendorId, order_date, delivery_date || null, total_amount, status || 'Draft', currency || 'ZAR', notes || null, user_id]
        );
        const purchaseId = purchaseResult.rows[0].id;

        for (const item of line_items) {
            if (!item.description || item.quantity == null || item.unit_cost == null || item.line_total == null) {
                throw new Error('Missing required line item fields');
            }
            await client.query(
                `INSERT INTO public.purchase_line_items (purchase_id, product_service_id, description, quantity, unit_cost, line_total, tax_rate)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [purchaseId, item.product_service_id || null, item.description, item.quantity, item.unit_cost, item.line_total, item.tax_rate || 0.00]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ id: purchaseId, message: 'Purchase created successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error creating purchase:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'Purchase order number already exists.' });
        }
        res.status(500).json({ error: 'Failed to create purchase', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// PUT Update Purchase
app.put('/api/purchases/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const { po_number, vendor_id, vendor_name, order_date, delivery_date, total_amount, status, currency, notes, line_items } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!order_date || total_amount == null || !line_items) {
        return res.status(400).json({ error: 'Missing required purchase fields or line items' });
    }

    // Validate vendor: either vendor_id or vendor_name must be present
    if (!vendor_id && (!vendor_name || vendor_name.trim() === '')) {
        return res.status(400).json({ error: 'Vendor ID or Vendor Name is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let finalVendorId = vendor_id;

        if (!finalVendorId) {
            const existingVendorResult = await pool.query('SELECT id FROM public.vendors WHERE LOWER(name) = LOWER($1) AND user_id = $2', [vendor_name.trim(), user_id]); // ADDED user_id filter

            if (existingVendorResult.rows.length > 0) {
                finalVendorId = existingVendorResult.rows[0].id;
            } else {
                const newVendorResult = await pool.query(
                    `INSERT INTO public.vendors (name, user_id) VALUES ($1, $2) RETURNING id`, // ADDED user_id
                    [vendor_name.trim(), user_id]
                );
                finalVendorId = newVendorResult.rows[0].id;
            }
        }

        const updatePurchaseResult = await client.query(
            `UPDATE public.purchases
             SET
               po_number = $1,
               vendor_id = $2,
               order_date = $3,
               delivery_date = $4,
               total_amount = $5,
               status = $6,
               currency = $7,
               notes = $8,
               updated_at = CURRENT_TIMESTAMP
             WHERE id = $9 AND user_id = $10 RETURNING id`, // ADDED user_id filter
            [po_number || null, finalVendorId, order_date, delivery_date || null, total_amount, status, currency || 'ZAR', notes || null, id, user_id]
        );

        if (updatePurchaseResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Purchase not found for update or unauthorized' });
        }

        await client.query('DELETE FROM public.purchase_line_items WHERE purchase_id = $1', [id]);

        for (const item of line_items) {
            if (!item.description || item.quantity == null || item.unit_cost == null || item.line_total == null) {
                throw new Error('Missing required line item fields');
            }
            await client.query(
                `INSERT INTO public.purchase_line_items (purchase_id, product_service_id, description, quantity, unit_cost, line_total, tax_rate)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [id, item.product_service_id || null, item.description, item.quantity, item.unit_cost, item.line_total, item.tax_rate || 0.00]
            );
        }

        await client.query('COMMIT');
        res.json({ id: id, message: 'Purchase updated successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error updating purchase:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'Purchase order number already exists.' });
        }
        res.status(500).json({ error: 'Failed to update purchase', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// DELETE Purchase
app.delete('/api/purchases/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query('DELETE FROM public.purchases WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Purchase not found or unauthorized' });
        }
        res.json({ message: 'Purchase deleted successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error deleting purchase:', error);
        res.status(500).json({ error: 'Failed to delete purchase', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Record Purchase Payment
app.post('/api/purchases/:id/payment', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params; // Purchase ID
    const { amount_paid, payment_date, notes, account_id, transaction_description, transaction_category } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (amount_paid == null || !payment_date || !account_id) {
        return res.status(400).json({ error: 'Amount paid, payment date, and account ID are required' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Check if the purchase belongs to the user
        const purchaseCheck = await client.query('SELECT id FROM public.purchases WHERE id = $1 AND user_id = $2', [id, user_id]);
        if (purchaseCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Purchase not found or unauthorized.' });
        }

        // 1. Create a transaction entry
        const transactionResult = await pool.query(
            `INSERT INTO public.transactions (type, amount, description, date, category, account_id, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, // ADDED user_id
            ['expense', amount_paid, transaction_description || `Payment for Purchase ${id}`, payment_date, transaction_category || 'Business Expenses', account_id, user_id]
        );
        const transactionId = transactionResult.rows[0].id;

        // 2. Create a purchase payment entry
        await client.query(
            `INSERT INTO public.purchase_payments (purchase_id, transaction_id, amount_paid, payment_date, notes, user_id)
             VALUES ($1, $2, $3, $4, $5, $6)`, // ADDED user_id
            [id, transactionId, amount_paid, payment_date, notes || null, user_id]
        );

        // Optional: Update purchase status if fully paid (requires more logic)

        await client.query('COMMIT');
        res.status(201).json({ message: 'Purchase payment recorded successfully', transaction_id: transactionId });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        await client.query('ROLLBACK');
        console.error('Error recording purchase payment:', error);
        res.status(500).json({ error: 'Failed to record purchase payment', detail: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

/* --- EMPLOYEES API (Existing, with slight modifications for clarity) --- */

// GET All Employees (List View)
app.get('/employees', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
const result = await pool.query(`
  SELECT
    e.id,
    e.name,
    e.position,
    e.email,
    e.id_number,
    e.phone,
    e.start_date,
    e.payment_type,
    e.base_salary,
    e.hourly_rate,
    COALESCE((
      SELECT SUM(hours_worked)
      FROM time_entries
      WHERE employee_id = e.id AND status = 'approved' AND user_id = $1
    ), 0) AS hours_worked_total,
    (e.bank_details::json->>'accountHolder') AS account_holder,
    (e.bank_details::json->>'bankName') AS bank_name,
    (e.bank_details::json->>'accountNumber') AS account_number,
    (e.bank_details::json->>'branchCode') AS branch_code
  FROM employees e
  WHERE e.user_id = $1
  ORDER BY e.name ASC;
`, [user_id]);

        res.json(result.rows);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching employees:', error);
        res.status(500).json({ error: 'Failed to fetch employees', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT Update Employee Details (including bank details and hours_worked_total)
// Employee Registration Endpoint
app.post('/employees', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.parent_user_id; // Get user_id from req.user
  const {
    name,
    position,
    email,
    idNumber,
    phone,
    startDate,
    paymentType,
    baseSalary,
    hourlyRate,
    bankDetails, // This will be an object
  } = req.body;

  // Basic validation
  if (!name || !position || !email || !idNumber || !startDate || !paymentType || !bankDetails) {
    return res.status(400).json({ error: 'Missing required employee fields.' });
  }
  if (paymentType === 'salary' && baseSalary === null) {
    return res.status(400).json({ error: 'Base salary is required for salary-based employees.' });
  }
  if (paymentType === 'hourly' && hourlyRate === null) {
    return res.status(400).json({ error: 'Hourly rate is required for hourly-based employees.' });
  }
  if (!bankDetails.accountHolder || !bankDetails.bankName || !bankDetails.accountNumber || !bankDetails.branchCode) {
    return res.status(400).json({ error: 'Missing required bank details.' });
  }

  try {
    // Check if an employee with the same ID number or email already exists for this user
    const existingEmployee = await pool.query(
      `SELECT id FROM employees WHERE user_id = $1 AND (id_number = $2 OR email = $3)`,
      [user_id, idNumber, email]
    );

    if (existingEmployee.rows.length > 0) {
      return res.status(409).json({ error: 'Employee with this ID number or email already exists for your account.' });
    }

    // Insert into employees table
    const result = await pool.query(
      `INSERT INTO employees (
        user_id,
        name,
        position,
        email,
        id_number,
        phone,
        start_date,
        payment_type,
        base_salary,
        hourly_rate,
        bank_details,
        created_at,
        updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING id, name;`, // Return id and name for confirmation
      [
        user_id,
        name,
        position,
        email,
        idNumber,
        phone,
        startDate,
        paymentType,
        baseSalary,
        hourlyRate,
        JSON.stringify(bankDetails), // Store bankDetails as JSONB
      ]
    );

    res.status(201).json({
      message: 'Employee registered successfully',
      employee: {
        id: result.rows[0].id,
        name: result.rows[0].name,
      },
    });

  } catch (error: unknown) {
    console.error('Error adding employee:', error);
    if (error instanceof Error) {
      // Check for specific PostgreSQL unique constraint error if needed
      // For example, if you had a unique constraint on (user_id, id_number)
      // if ((error as any).code === '23505') {
      //   return res.status(409).json({ error: 'An employee with this ID number already exists.' });
      // }
      res.status(500).json({ error: 'Failed to add employee', details: error.message });
    } else {
      res.status(500).json({ error: 'Failed to add employee', details: String(error) });
    }
  }
});

// DELETE Employee
app.delete('/employees/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        // Due to ON DELETE CASCADE, bank_details and time_entries will be deleted automatically
        // Ensure deletion is scoped by user_id
        const result = await pool.query('DELETE FROM employees WHERE id = $1 AND user_id = $2 RETURNING id', [id, user_id]); // ADDED user_id filter
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Employee not found or unauthorized' });
        }
        res.json({ message: 'Employee deleted successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error deleting employee:', error);
        res.status(500).json({ error: 'Failed to delete employee', detail: error instanceof Error ? error.message : String(error) });
    }
});


/* --- TIME ENTRIES API --- */

// NEW: GET All Time Entries (for dashboard and general list)
app.get('/time-entries', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query(`
            SELECT te.id, te.employee_id, te.entry_date as date, te.hours_worked, te.notes as description, te.status, te.created_at, te.updated_at
            FROM time_entries te
            JOIN employees e ON te.employee_id = e.id
            WHERE e.user_id = $1 -- Filter by user_id
            ORDER BY te.entry_date DESC, te.created_at DESC
        `, [user_id]); // Pass user_id as a parameter
        res.json(result.rows);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching all time entries:', error);
        res.status(500).json({ error: 'Failed to fetch all time entries', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Time Entries for a specific employee
app.get('/employees/:employeeId/time-entries', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { employeeId } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        // Ensure the employee belongs to the user before fetching their time entries
        const employeeCheck = await pool.query('SELECT id FROM employees WHERE id = $1 AND user_id = $2', [employeeId, user_id]);
        if (employeeCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Employee not found or unauthorized to view their time entries.' });
        }

        const result = await pool.query(
            `SELECT id, employee_id, entry_date as date, hours_worked, notes as description, status, created_at, updated_at
             FROM time_entries
             WHERE employee_id = $1
             ORDER BY entry_date DESC`,
            [employeeId]
        );
        res.json(result.rows);
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching time entries for employee:', error);
        res.status(500).json({ error: 'Failed to fetch time entries', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Add a new Time Entry for an employee
app.post('/employees/:employeeId/time-entries', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { employeeId } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const { date, hours_worked, description } = req.body; // Use date, hours_worked, description to match frontend payload

    if (!date || hours_worked == null || hours_worked <= 0) {
        return res.status(400).json({ error: 'Date and positive hours worked are required.' });
    }

    try {
        // Ensure the employee belongs to the user before adding a time entry for them
        const employeeCheck = await pool.query('SELECT id FROM employees WHERE id = $1 AND user_id = $2', [employeeId, user_id]);
        if (employeeCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Employee not found or unauthorized to add time entries for them.' });
        }

        const result = await pool.query(
  `INSERT INTO time_entries (employee_id, entry_date, hours_worked, notes, status, user_id)
   VALUES ($1, $2, $3, $4, $5, $6)
   RETURNING id, employee_id, entry_date as date, hours_worked, notes as description, status`,
  [employeeId, date, hours_worked, description || null, 'pending', user_id]
);

        res.status(201).json(result.rows[0]); // Return the created time entry object
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error adding time entry:', error);
        res.status(500).json({ error: 'Failed to add time entry', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT Update a specific Time Entry
app.put('/time-entries/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const { date, hours_worked, description, status } = req.body; // Allow status to be updated

    // Build dynamic query parts
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (date !== undefined) { updates.push(`entry_date = $${paramIndex++}`); values.push(date); }
    if (hours_worked !== undefined) { updates.push(`hours_worked = $${paramIndex++}`); values.push(hours_worked); }
    if (description !== undefined) { updates.push(`notes = $${paramIndex++}`); values.push(description); }
    if (status !== undefined) { updates.push(`status = $${paramIndex++}`); values.push(status); }

    if (updates.length === 0) {
        return res.status(400).json({ error: 'No fields provided for update.' });
    }

    updates.push(`updated_at = CURRENT_TIMESTAMP`); // Always update timestamp

    // Add user_id to the WHERE clause for security
    values.push(id); // The ID for WHERE id = $X
    values.push(user_id); // The user_id for WHERE user_id = $Y

    try {
        const result = await pool.query(
            `UPDATE time_entries te
             SET ${updates.join(', ')}
             FROM employees e
             WHERE te.employee_id = e.id AND te.id = $${paramIndex} AND e.user_id = $${paramIndex + 1}
             RETURNING te.id, te.employee_id, te.entry_date as date, te.hours_worked, te.notes as description, te.status`, // Return updated object
            values
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Time entry not found or unauthorized' });
        }
        res.json(result.rows[0]); // Return the updated time entry object
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error updating time entry:', error);
        res.status(500).json({ error: 'Failed to update time entry', detail: error instanceof Error ? error.message : String(error) });
    }
});

// DELETE a specific Time Entry
app.delete('/time-entries/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        // Ensure deletion is scoped by user_id by joining with employees table
        const result = await pool.query(
            `DELETE FROM time_entries te
             USING employees e
             WHERE te.employee_id = e.id AND te.id = $1 AND e.user_id = $2
             RETURNING te.id`,
            [id, user_id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Time entry not found or unauthorized' });
        }
        res.json({ message: 'Time entry deleted successfully' });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error deleting time entry:', error);
        res.status(500).json({ error: 'Failed to delete time entry', detail: error instanceof Error ? error.message : String(error) });
    }
});

/* **START OF REPLACED/MODIFIED SUPPLIER ROUTES** */

/* --- Supplier API (Replacing existing /vendors routes) --- */

// GET All Suppliers (and filter by search term if provided)
app.get('/api/suppliers', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    // Asserting req.query.search as string to allow .toLowerCase()
    const searchTerm = req.query.search as string | undefined;

    let query = 'SELECT id, name, email, phone, address, vat_number, total_purchased FROM public.suppliers WHERE user_id = $1'; // ADDED user_id filter
    const queryParams: (string | number)[] = [user_id]; // Initialize with user_id
    let paramIndex = 2; // Start index at 2 because $1 is user_id

    if (searchTerm) {
        query += ` AND (LOWER(name) ILIKE $${paramIndex} OR LOWER(email) ILIKE $${paramIndex})`;
        queryParams.push(`%${searchTerm.toLowerCase()}%`);
    }

    query += ' ORDER BY name ASC';

    try {
        const { rows } = await pool.query<SupplierDB>(query, queryParams);
        const formattedRows = rows.map(mapSupplierToFrontend);
        res.json(formattedRows);
    } catch (error: unknown) { // Explicitly type error as unknown
        console.error('Error fetching suppliers:', error);
        res.status(500).json({ error: 'Failed to fetch suppliers', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET a single supplier by ID (useful for "Eye" button or detailed view)
app.get('/api/suppliers/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const { rows } = await pool.query<SupplierDB>(
            'SELECT id, name, email, phone, address, vat_number, total_purchased FROM public.suppliers WHERE id = $1 AND user_id = $2', // ADDED user_id filter
            [id, user_id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Supplier not found or unauthorized' });
        }
        res.json(mapSupplierToFrontend(rows[0]));
    } catch (error: unknown) {
        console.error(`Error fetching supplier with ID ${id}:`, error);
        res.status(500).json({ error: 'Failed to fetch supplier', detail: error instanceof Error ? error.message : String(error) });
    }
});


// POST Create New Supplier
app.post('/api/suppliers', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { name, email, phone, address, vatNumber } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!name) {
        return res.status(400).json({ error: 'Supplier name is required' });
    }

    try {
        const result = await pool.query<SupplierDB>(
            `INSERT INTO public.suppliers (name, email, phone, address, vat_number, user_id)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, phone, address, vat_number, total_purchased`,
            [name, email || null, phone || null, address || null, vatNumber || null, user_id] // ADDED user_id
        );
        res.status(201).json(mapSupplierToFrontend(result.rows[0]));
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error adding supplier:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') { // Check for unique violation
            return res.status(409).json({ error: 'A supplier with this email or VAT number already exists.' });
        }
        res.status(500).json({ error: 'Failed to add supplier', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT Update Existing Supplier
app.put('/api/suppliers/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const { name, email, phone, address, vatNumber } = req.body;

    if (!name) { // Name is required for update
        return res.status(400).json({ error: 'Supplier name is required for update.' });
    }

    try {
        const result = await pool.query<SupplierDB>(
            `UPDATE public.suppliers
             SET name = $1, email = $2, phone = $3, address = $4, vat_number = $5, updated_at = CURRENT_TIMESTAMP
             WHERE id = $6 AND user_id = $7 RETURNING id, name, email, phone, address, vat_number, total_purchased`, // ADDED user_id filter
            [name, email || null, phone || null, address || null, vatNumber || null, id, user_id] // ADDED user_id
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Supplier not found or unauthorized.' });
        }
        res.json(mapSupplierToFrontend(result.rows[0]));
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error(`Error updating supplier with ID ${id}:`, error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'A supplier with this email or VAT number already exists.' });
        }
        res.status(500).json({ error: 'Failed to update supplier', detail: error instanceof Error ? error.message : String(error) });
    }
});

// DELETE a Supplier
app.delete('/api/suppliers/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    try {
        const { rowCount } = await pool.query(
            'DELETE FROM public.suppliers WHERE id = $1 AND user_id = $2', // ADDED user_id filter
            [id, user_id]
        );

        if (rowCount === 0) {
            return res.status(404).json({ error: 'Supplier not found or unauthorized.' });
        }
        res.status(204).send(); // No Content for successful deletion
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error(`Error deleting supplier with ID ${id}:`, error);
        if (error instanceof Error && 'code' in error && error.code === '23503') { // PostgreSQL foreign key violation error
            return res.status(409).json({
                error: 'Cannot delete supplier: associated with existing purchase orders or other records.',
                detail: error.message
            });
        }
        res.status(500).json({ error: 'Failed to delete supplier', detail: error instanceof Error ? error.message : String(error) });
    }
});

/* --- Product API Endpoints --- */

// Helper function to get tax_rate_id from vatRate (value)
// This will be used in POST and PUT operations
const getTaxRateIdFromVatRate = async (rate: number | undefined): Promise<number | null> => {
    if (rate === undefined || rate === null) {
        return null;
    }
    try {
        const { rows } = await pool.query<{ tax_rate_id: number }>('SELECT tax_rate_id FROM public.tax_rates WHERE rate = $1', [rate]);
        if (rows.length > 0) {
            return rows[0].tax_rate_id;
        }
        // Optionally, if the rate doesn't exist, you could insert it here,
        // or return null and let the calling function handle it (e.g., error).
        // For simplicity, we'll return null if not found.
        return null;
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching tax_rate_id by rate:', error);
        return null; // Or throw to propagate the error
    }
};
// Interface for database product data
interface ProductDB {
  id: number;
  name: string;
  description: string | null;
  unit_price: number;
  cost_price: number | null;
  sku: string | null;
  is_service: boolean;
  stock_quantity: number;
  created_at: Date;
  updated_at: Date;
  tax_rate_id: number | null;
  category: string | null;
  unit: string | null;
  tax_rate_value?: number; // Joined from tax_rates
  min_quantity?: number | null; // Added
  max_quantity?: number | null; // Added
  available_value?: number | null; // Added
  user_id: string; // Added user_id to ProductDB
}

// Interface for product data received in POST/PUT requests
interface CreateUpdateProductBody {
    name: string;
    description?: string;
    price: number; // Frontend sends sellingPrice as 'price'
    costPrice?: number;
    sku?: string;
    isService?: boolean; // Frontend sends 'isService'
    stock?: number; // Frontend sends 'qty' as 'stock'
    vatRate?: number;
    category?: string;
    unit?: string;
    minQty?: number; // ADDED
    maxQty?: number; // ADDED
    availableValue?: number; // ADDED
}

// GET All Products (with optional search)
// Path: /api/products
// GET All Products (with optional search)
// Path: /api/products
app.get('/api/products', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const searchTerm = req.query.search as string | undefined;

    let query = `
        SELECT
            ps.id, ps.name, ps.description, ps.unit_price, ps.cost_price, ps.sku,
            ps.is_service, ps.stock_quantity, ps.created_at, ps.updated_at,
            ps.tax_rate_id, ps.category, ps.unit, tr.rate AS tax_rate_value,
            ps.min_quantity, ps.max_quantity, ps.available_value, ps.user_id -- ADDED min_quantity, max_quantity, available_value, user_id
        FROM public.products_services ps
        LEFT JOIN public.tax_rates tr ON ps.tax_rate_id = tr.tax_rate_id
        WHERE ps.user_id = $1
    `;
    const queryParams: (string | number)[] = [user_id];
    let paramIndex = 2;

    if (searchTerm) {
        query += ` AND (LOWER(ps.name) ILIKE $${paramIndex} OR LOWER(ps.description) ILIKE $${paramIndex} OR LOWER(ps.sku) ILIKE $${paramIndex} OR LOWER(ps.category) ILIKE $${paramIndex})`;
        queryParams.push(`%${searchTerm.toLowerCase()}%`);
    }

    query += ' ORDER BY ps.name ASC';

    try {
        const { rows } = await pool.query<ProductDB>(query, queryParams);
        const formattedRows = rows.map(mapProductToFrontend);
        res.json(formattedRows);
    } catch (error: unknown) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Failed to fetch products', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET a single product by ID
// Path: /api/products/:id
app.get('/api/products/:id', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const { rows } = await pool.query<ProductDB>(
            `SELECT
                ps.id, ps.name, ps.description, ps.unit_price, ps.cost_price, ps.sku,
                ps.is_service, ps.stock_quantity, ps.created_at, ps.updated_at,
                ps.tax_rate_id, ps.category, ps.unit, tr.rate AS tax_rate_value,
                ps.min_quantity, ps.max_quantity, ps.available_value, ps.user_id -- ADDED min_quantity, max_quantity, available_value, user_id
             FROM public.products_services ps
             LEFT JOIN public.tax_rates tr ON ps.tax_rate_id = tr.tax_rate_id
             WHERE ps.id = $1 AND ps.user_id = $2`,
            [id, user_id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Product not found or unauthorized' });
        }
        res.json(mapProductToFrontend(rows[0]));
    } catch (error: unknown) {
        console.error(`Error fetching product with ID ${id}:`, error);
        res.status(500).json({ error: 'Failed to fetch product', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Create New Product
// Path: /api/products
app.post('/api/products', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const {
        name, description, price, costPrice, sku,
        isService = false, stock = 0, vatRate, category, unit,
        minQty = 0, maxQty = 0, availableValue = 0 // ADDED minQty, maxQty, availableValue with defaults
    }: CreateUpdateProductBody = req.body;

    // Basic validation
    if (!name || price === undefined || price === null) {
        return res.status(400).json({ error: 'Product name and price are required.' });
    }
    if (typeof price !== 'number' || price < 0) {
        return res.status(400).json({ error: 'Price must be a non-negative number.' });
    }

    const taxRateId = await getTaxRateIdFromVatRate(vatRate);

    if (vatRate !== undefined && vatRate !== null && taxRateId === null) {
        return res.status(400).json({ error: `Provided VAT rate ${vatRate} does not exist in tax_rates.` });
    }

    try {
        const result = await pool.query<ProductDB>(
            `INSERT INTO public.products_services (
                name, description, unit_price, cost_price, sku, is_service,
                stock_quantity, tax_rate_id, category, unit, user_id,
                min_quantity, max_quantity, available_value -- ADDED columns
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) -- ADDED values
            RETURNING
                id, name, description, unit_price, cost_price, sku,
                is_service, stock_quantity, created_at, updated_at,
                tax_rate_id, category, unit, min_quantity, max_quantity, available_value, user_id`, // ADDED returning fields
            [
                name,
                description || null,
                price,
                costPrice || null,
                sku || null,
                isService,
                stock,
                taxRateId,
                category || null,
                unit || null,
                user_id,
                minQty, // ADDED
                maxQty, // ADDED
                availableValue // ADDED
            ]
        );

        const newProductDb = result.rows[0];
        if (newProductDb.tax_rate_id) {
            const { rows: taxRows } = await pool.query<{ rate: number }>('SELECT rate FROM public.tax_rates WHERE tax_rate_id = $1', [newProductDb.tax_rate_id]);
            if (taxRows.length > 0) {
                newProductDb.tax_rate_value = taxRows[0].rate;
            }
        }
        res.status(201).json(mapProductToFrontend(newProductDb));

    } catch (error: unknown) {
        console.error('Error adding product:', error);
        if (error instanceof Error && 'code' in error) {
            if (error.code === '23505') {
                return res.status(409).json({ error: 'A product with this SKU already exists.' });
            }
            if (error.code === '23503') {
                return res.status(400).json({ error: 'Invalid VAT rate ID provided.', detail: error.message });
            }
        }
        res.status(500).json({ error: 'Failed to add product', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT Update Existing Product
// Path: /api/products/:id
app.put('/api/products/:id', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const {
        name, description, price, costPrice, sku,
        isService, stock, vatRate, category, unit,
        minQty, maxQty, availableValue // ADDED minQty, maxQty, availableValue
    }: CreateUpdateProductBody = req.body;

    // Construct dynamic update query
    const updates: string[] = [];
    const values: (string | number | boolean | null)[] = [];
    let paramIndex = 1;

    if (name !== undefined) { updates.push(`name = $${paramIndex++}`); values.push(name); }
    if (description !== undefined) { updates.push(`description = $${paramIndex++}`); values.push(description || null); }
    if (price !== undefined) {
        if (typeof price !== 'number' || price < 0) {
            return res.status(400).json({ error: 'Price must be a non-negative number.' });
        }
        updates.push(`unit_price = $${paramIndex++}`); values.push(price);
    }
    if (costPrice !== undefined) { updates.push(`cost_price = $${paramIndex++}`); values.push(costPrice || null); }
    if (sku !== undefined) { updates.push(`sku = $${paramIndex++}`); values.push(sku || null); }
    if (isService !== undefined) { updates.push(`is_service = $${paramIndex++}`); values.push(isService); }
    if (stock !== undefined) { updates.push(`stock_quantity = $${paramIndex++}`); values.push(stock); }
    if (category !== undefined) { updates.push(`category = $${paramIndex++}`); values.push(category || null); }
    if (unit !== undefined) { updates.push(`unit = $${paramIndex++}`); values.push(unit || null); }
    if (minQty !== undefined) { updates.push(`min_quantity = $${paramIndex++}`); values.push(minQty); } // ADDED
    if (maxQty !== undefined) { updates.push(`max_quantity = $${paramIndex++}`); values.push(maxQty); } // ADDED
    if (availableValue !== undefined) { updates.push(`available_value = $${paramIndex++}`); values.push(availableValue); } // ADDED


    let taxRateId: number | null | undefined;
    if (vatRate !== undefined) {
        taxRateId = await getTaxRateIdFromVatRate(vatRate);
        if (vatRate !== null && taxRateId === null) {
            return res.status(400).json({ error: `Provided VAT rate ${vatRate} does not exist in tax_rates.` });
        }
        updates.push(`tax_rate_id = $${paramIndex++}`); values.push(taxRateId);
    }


    if (updates.length === 0) {
        return res.status(400).json({ error: 'No fields provided for update.' });
    }

    updates.push(`updated_at = CURRENT_TIMESTAMP`); // Always update timestamp

    const query = `UPDATE public.products_services SET ${updates.join(', ')} WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1} RETURNING id, name, description, unit_price, cost_price, sku, is_service, stock_quantity, created_at, updated_at, tax_rate_id, category, unit, min_quantity, max_quantity, available_value, user_id`; // ADDED returning fields
    values.push(id);
    values.push(user_id);

    try {
        const result = await pool.query<ProductDB>(query, values);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found or unauthorized.' });
        }
        const updatedProductDb = result.rows[0];
        if (updatedProductDb.tax_rate_id) {
            const { rows: taxRows } = await pool.query<{ rate: number }>('SELECT rate FROM public.tax_rates WHERE tax_rate_id = $1', [updatedProductDb.tax_rate_id]);
            if (taxRows.length > 0) {
                updatedProductDb.tax_rate_value = taxRows[0].rate;
            }
        }
        res.json(mapProductToFrontend(updatedProductDb));

    } catch (error: unknown) {
        console.error(`Error updating product with ID ${id}:`, error);
        if (error instanceof Error && 'code' in error) {
            if (error.code === '23505') {
                return res.status(409).json({ error: 'A product with this SKU already exists.' });
            }
            if (error.code === '23503') {
                return res.status(400).json({ error: 'Invalid VAT rate ID provided.', detail: error.message });
            }
        }
        res.status(500).json({ error: 'Failed to update product', detail: error instanceof Error ? error.message : String(error) });
    }
});

// DELETE a Product
// Path: /api/products/:id
app.delete('/api/products/:id', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    try {
        const { rowCount } = await pool.query(
            'DELETE FROM public.products_services WHERE id = $1 AND user_id = $2',
            [id, user_id]
        );

        if (rowCount === 0) {
            return res.status(404).json({ error: 'Product not found or unauthorized.' });
        }
        res.status(204).send(); // No Content for successful deletion
    } catch (error: unknown) {
        console.error(`Error deleting product with ID ${id}:`, error);
        if (error instanceof Error && 'code' in error && error.code === '23503') {
            return res.status(409).json({
                error: 'Cannot delete product: associated with existing records (e.g., invoices).',
                detail: error.message
            });
        }
        res.status(500).json({ error: 'Failed to delete product', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Products/Services (This seems like a duplicate of /api/products but without search)
// Keeping it for now as it was in your provided snippet, but consider consolidating.
app.get('/products-services', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(
      `SELECT id, name, description, unit_price, cost_price, sku, is_service, stock_quantity, unit,
              min_quantity, max_quantity, available_value, user_id -- ADDED min_quantity, max_quantity, available_value, user_id
       FROM products_services WHERE user_id = $1 ORDER BY name`, [user_id]
    );

    const formattedRows = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      unit_price: Number(row.unit_price),
      cost_price: row.cost_price ? Number(row.cost_price) : null,
      sku: row.sku,
      is_service: row.is_service,
      stock_quantity: parseInt(row.stock_quantity, 10),
      created_at: row.created_at,
      updated_at: row.updated_at,
      tax_rate_id: row.tax_rate_id,
      category: row.category,
      unit: row.unit,
      tax_rate_value: row.tax_rate_value, // If this is joined, ensure it's handled
      min_quantity: row.min_quantity !== null ? Number(row.min_quantity) : null, // Added
      max_quantity: row.max_quantity !== null ? Number(row.max_quantity) : null, // Added
      available_value: row.available_value !== null ? Number(row.available_value) : null, // Added
      user_id: row.user_id, // Added
    }));

    res.json(formattedRows);
  } catch (error: unknown) {
    console.error('Error fetching products/services:', error);
    res.status(500).json({ error: 'Failed to fetch products/services', detail: error instanceof Error ? error.message : String(error) });
  }
});

// POST Product/Service (This also seems like a duplicate of /api/products but with different payload keys)
// Keeping it for now as it was in your provided snippet, but consider consolidating.
app.post('/products-services', authMiddleware, async (req: Request, res: Response) => {
  const { name, description, unit_price, cost_price, sku, is_service, stock_quantity } = req.body;
  const user_id = req.user!.parent_user_id;
  if (!name || unit_price == null) {
    return res.status(400).json({ error: 'Product/Service name and unit_price are required' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO products_services (name, description, unit_price, cost_price, sku, is_service, stock_quantity, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [name, description || null, unit_price, cost_price || null, sku || null, is_service || false, stock_quantity || 0, user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (error: unknown) {
    console.error('Error adding product/service:', error);
    res.status(500).json({ error: 'Failed to add product/service', detail: error instanceof Error ? error.message : String(error) });
  }
});

// PUT Update Product Stock
app.put('/api/products-services/:id/stock', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { adjustmentQuantity } = req.body;
  const user_id = req.user!.parent_user_id;

  const parsedAdjustmentQuantity = Number(adjustmentQuantity);

  if (typeof parsedAdjustmentQuantity !== 'number' || isNaN(parsedAdjustmentQuantity)) {
    return res.status(400).json({ error: 'adjustmentQuantity must be a valid number.' });
  }

  try {
    await pool.query('BEGIN');

    const productResult = await pool.query(
      'SELECT stock_quantity, name FROM public.products_services WHERE id = $1 AND user_id = $2 FOR UPDATE',
      [id, user_id]
    );

    if (productResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Product or service not found or unauthorized.' });
    }

    const currentStock = Number(productResult.rows[0].stock_quantity);
    const productName = productResult.rows[0].name;

    const newStock = currentStock + parsedAdjustmentQuantity;

    if (parsedAdjustmentQuantity < 0 && newStock < 0) {
      await pool.query('ROLLBACK');
      return res.status(400).json({
        error: `Insufficient stock for "${productName}". Current stock: ${currentStock}. Cannot sell ${Math.abs(parsedAdjustmentQuantity)}.`,
        availableStock: currentStock,
      });
    }

    const updateResult = await pool.query(
      `UPDATE public.products_services
       SET stock_quantity = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2 AND user_id = $3
       RETURNING id, name, stock_quantity`,
      [newStock, id, user_id]
    );

    await pool.query('COMMIT');

    res.json({
      message: `Stock for "${updateResult.rows[0].name}" updated successfully.`,
      product: updateResult.rows[0],
    });

  } catch (error: unknown) {
    await pool.query('ROLLBACK');
    console.error(`Error updating stock for product ID ${id}:`, error);
    res.status(500).json({
      error: 'Failed to update product stock',
      detail: error instanceof Error ? error.message : String(error)
    });
  }
});

/* --- Stats API Endpoints --- */

// Helper function to calculate change percentage and type
const calculateChange = (current: number, previous: number) => {
    if (previous === 0 && current === 0) {
        return { changePercentage: 0, changeType: 'neutral' };
    }
    if (previous === 0) { // If previous was 0 and current is not, it's an increase
        return { changePercentage: 100, changeType: 'increase' }; // Or a very large number, but 100% is clear
    }
    const percentage = ((current - previous) / previous) * 100;
    let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';
    if (percentage > 0) {
        changeType = 'increase';
    } else if (percentage < 0) {
        changeType = 'decrease';
    }
    return { changePercentage: parseFloat(percentage.toFixed(2)), changeType };
};

// Define a common date range for "current" and "previous" periods (e.g., last 30 days vs. prior 30 days)
const getCurrentAndPreviousDateRanges = () => {
    const now = new Date();
    const currentPeriodEnd = now.toISOString();

    const currentPeriodStart = new Date();
    currentPeriodStart.setDate(now.getDate() - 30); // Last 30 days
    const currentPeriodStartISO = currentPeriodStart.toISOString();

    const previousPeriodEnd = currentPeriodStart.toISOString();
    const previousPeriodStart = new Date(currentPeriodStart);
    previousPeriodStart.setDate(currentPeriodStart.getDate() - 30); // 30 days before that
    const previousPeriodStartISO = previousPeriodStart.toISOString();

    return {
        currentStart: currentPeriodStartISO,
        currentEnd: currentPeriodEnd,
        previousStart: previousPeriodStartISO,
        previousEnd: previousPeriodEnd
    };
};


// GET Client Count with Change
// GET Quotes Stats
app.get('/api/stats/quotes', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    const { startDate, endDate } = req.query;

    try {
        let dateFilter = '';
        const queryParams: (string | number)[] = [user_id];
        let paramIndex = 2;

        if (startDate) {
            dateFilter += ` AND created_at >= $${paramIndex++}`;
            queryParams.push(startDate as string);
        }
        if (endDate) {
            dateFilter += ` AND created_at <= $${paramIndex++}`;
            queryParams.push(endDate as string);
        }

        const currentResult = await pool.query(`
            SELECT COUNT(id) AS count
            FROM public.quotations
            WHERE user_id = $1 ${dateFilter};
        `, queryParams);
        const currentCount = parseInt(currentResult.rows[0]?.count || 0, 10);

        let previousStartDate: string | null = null;
        let previousEndDate: string | null = null;

        if (startDate && endDate) {
            const start = new Date(startDate as string);
            const end = new Date(endDate as string);
            const durationMs = end.getTime() - start.getTime();

            const prevEnd = new Date(start.getTime() - 1);
            const prevStart = new Date(prevEnd.getTime() - durationMs);

            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        } else if (endDate) {
            const end = new Date(endDate as string);
            const prevEnd = new Date(end.getTime() - 1);
            const prevStart = new Date(prevEnd.getTime() - (30 * 24 * 60 * 60 * 1000));
            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        } else if (startDate) {
            const start = new Date(startDate as string);
            const prevStart = new Date(start.getTime() - (30 * 24 * 60 * 60 * 1000));
            const prevEnd = new Date(start.getTime() - 1);
            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        }

        let previousDateFilter = '';
        const previousQueryParams: (string | number)[] = [user_id];
        let prevParamIndex = 2;

        if (previousStartDate) {
            previousDateFilter += ` AND created_at >= $${prevParamIndex++}`;
            previousQueryParams.push(previousStartDate);
        }
        if (previousEndDate) {
            previousDateFilter += ` AND created_at <= $${prevParamIndex++}`;
            previousQueryParams.push(previousEndDate);
        }

        const previousResult = await pool.query(`
            SELECT COUNT(id) AS count
            FROM public.quotations
            WHERE user_id = $1 ${previousDateFilter};
        `, previousQueryParams);
        const previousCount = parseInt(previousResult.rows[0]?.count || 0, 10);

        const { changePercentage, changeType } = calculateChange(currentCount, previousCount);

        res.json({
            count: currentCount,
            previousCount: previousCount,
            changePercentage,
            changeType,
        });

    } catch (error: unknown) {
        console.error('Error fetching quotes stats:', error);
        res.status(500).json({ error: 'Failed to fetch quotes stats', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Invoices Stats
app.get('/api/stats/invoices', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    const { startDate, endDate } = req.query;

    try {
        let dateFilter = '';
        const queryParams: (string | number)[] = [user_id];
        let paramIndex = 2;

        if (startDate) {
            dateFilter += ` AND created_at >= $${paramIndex++}`;
            queryParams.push(startDate as string);
        }
        if (endDate) {
            dateFilter += ` AND created_at <= $${paramIndex++}`;
            queryParams.push(endDate as string);
        }

        const currentResult = await pool.query(`
            SELECT COUNT(id) AS count
            FROM public.invoices
            WHERE user_id = $1 ${dateFilter};
        `, queryParams);
        const currentCount = parseInt(currentResult.rows[0]?.count || 0, 10);

        let previousStartDate: string | null = null;
        let previousEndDate: string | null = null;

        if (startDate && endDate) {
            const start = new Date(startDate as string);
            const end = new Date(endDate as string);
            const durationMs = end.getTime() - start.getTime();

            const prevEnd = new Date(start.getTime() - 1);
            const prevStart = new Date(prevEnd.getTime() - durationMs);

            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        } else if (endDate) {
            const end = new Date(endDate as string);
            const prevEnd = new Date(end.getTime() - 1);
            const prevStart = new Date(prevEnd.getTime() - (30 * 24 * 60 * 60 * 1000));
            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        } else if (startDate) {
            const start = new Date(startDate as string);
            const prevStart = new Date(start.getTime() - (30 * 24 * 60 * 60 * 1000));
            const prevEnd = new Date(start.getTime() - 1);
            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        }

        let previousDateFilter = '';
        const previousQueryParams: (string | number)[] = [user_id];
        let prevParamIndex = 2;

        if (previousStartDate) {
            previousDateFilter += ` AND created_at >= $${prevParamIndex++}`;
            previousQueryParams.push(previousStartDate);
        }
        if (previousEndDate) {
            previousDateFilter += ` AND created_at <= $${prevParamIndex++}`;
            previousQueryParams.push(previousEndDate);
        }

        const previousResult = await pool.query(`
            SELECT COUNT(id) AS count
            FROM public.invoices
            WHERE user_id = $1 ${previousDateFilter};
        `, previousQueryParams);
        const previousCount = parseInt(previousResult.rows[0]?.count || 0, 10);

        const { changePercentage, changeType } = calculateChange(currentCount, previousCount);

        res.json({
            count: currentCount,
            previousCount: previousCount,
            changePercentage,
            changeType,
        });

    } catch (error: unknown) {
        console.error('Error fetching invoices stats:', error);
        res.status(500).json({ error: 'Failed to fetch invoices stats', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Invoice Value Stats
app.get('/api/stats/invoice-value', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    const { startDate, endDate } = req.query;

    try {
        let dateFilter = '';
        const queryParams: (string | number)[] = [user_id];
        let paramIndex = 2;

        if (startDate) {
            dateFilter += ` AND created_at >= $${paramIndex++}`;
            queryParams.push(startDate as string);
        }
        if (endDate) {
            dateFilter += ` AND created_at <= $${paramIndex++}`;
            queryParams.push(endDate as string);
        }

        const currentResult = await pool.query(`
            SELECT COALESCE(SUM(total_amount), 0) AS value
            FROM public.invoices
            WHERE user_id = $1 ${dateFilter};
        `, queryParams);
        const currentValue = parseFloat(currentResult.rows[0]?.value || 0);

        let previousStartDate: string | null = null;
        let previousEndDate: string | null = null;

        if (startDate && endDate) {
            const start = new Date(startDate as string);
            const end = new Date(endDate as string);
            const durationMs = end.getTime() - start.getTime();

            const prevEnd = new Date(start.getTime() - 1);
            const prevStart = new Date(prevEnd.getTime() - durationMs);

            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        } else if (endDate) {
            const end = new Date(endDate as string);
            const prevEnd = new Date(end.getTime() - 1);
            const prevStart = new Date(prevEnd.getTime() - (30 * 24 * 60 * 60 * 1000));
            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        } else if (startDate) {
            const start = new Date(startDate as string);
            const prevStart = new Date(start.getTime() - (30 * 24 * 60 * 60 * 1000));
            const prevEnd = new Date(start.getTime() - 1);
            previousStartDate = prevStart.toISOString().split('T')[0];
            previousEndDate = prevEnd.toISOString().split('T')[0];
        }

        let previousDateFilter = '';
        const previousQueryParams: (string | number)[] = [user_id];
        let prevParamIndex = 2;

        if (previousStartDate) {
            previousDateFilter += ` AND created_at >= $${prevParamIndex++}`;
            previousQueryParams.push(previousStartDate);
        }
        if (previousEndDate) {
            previousDateFilter += ` AND created_at <= $${prevParamIndex++}`;
            previousQueryParams.push(previousEndDate);
        }

        const previousResult = await pool.query(`
            SELECT COALESCE(SUM(total_amount), 0) AS value
            FROM public.invoices
            WHERE user_id = $1 ${previousDateFilter};
        `, previousQueryParams);
        const previousValue = parseFloat(previousResult.rows[0]?.value || 0);

        const { changePercentage, changeType } = calculateChange(currentValue, previousValue);

        res.json({
            value: currentValue,
            previousValue: previousValue,
            changePercentage,
            changeType,
        });

    } catch (error: unknown) {
        console.error('Error fetching invoice value stats:', error);
        res.status(500).json({ error: 'Failed to fetch invoice value stats', detail: error instanceof Error ? error.message : String(error) });
    }
});

// STAT APIs
// Helper to format month to YYYY-MM
const formatMonth = (date: Date) => {
    return `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, '0')}`;
};

// GET Revenue Trend Data (Profit, Expenses, Revenue by Month)
// GET Revenue Trend Data (Profit, Expenses, Revenue by Month)
// GET Revenue Trend Data (Profit, Expenses, Revenue by Month)
app.get('/api/charts/revenue-trend', authMiddleware, async (req: Request, res: Response) => {
    // Get the authenticated user's parent_user_id from the request object
    const user_id = req.user!.parent_user_id;

    // Extract startDate and endDate from query parameters, if provided
    const { startDate, endDate } = req.query;

    try {
        // --- Revenue Transactions Query Construction ---
        // This filter will be applied to transactions identified as revenue
        let revenueDateFilter = '';
        const revenueQueryParams: (string | number)[] = [user_id]; // Parameters specific to the revenue transaction query
        let revenueParamIndex = 2; // Start index for additional parameters for revenue

        if (startDate) {
            revenueDateFilter += ` AND date >= $${revenueParamIndex++}`;
            revenueQueryParams.push(startDate as string);
        }
        if (endDate) {
            revenueDateFilter += ` AND date <= $${revenueParamIndex++}`;
            revenueQueryParams.push(endDate as string);
        }

        // --- Expense Transactions Query Construction ---
        // This filter will be applied to transactions identified as expenses
        let expenseDateFilter = '';
        const expenseQueryParams: (string | number)[] = [user_id]; // Parameters specific to the expense transaction query
        let expenseParamIndex = 2; // Start index for additional parameters for expenses

        if (startDate) {
            expenseDateFilter += ` AND date >= $${expenseParamIndex++}`;
            expenseQueryParams.push(startDate as string);
        }
        if (endDate) {
            expenseDateFilter += ` AND date <= $${expenseParamIndex++}`;
            expenseQueryParams.push(endDate as string);
        }

        // Fetch revenue from public.transactions by month with date and category filtering
        // Assuming 'type' for revenue transactions is 'income' or similar.
        // If your revenue transactions don't have a specific 'type', you can remove `AND type = 'income'`.
        const revenueTransactionsResult = await pool.query(`
            SELECT
                TO_CHAR(date, 'YYYY-MM') AS month,
                COALESCE(SUM(amount), 0) AS revenue
            FROM public.transactions
            WHERE
                user_id = $1
                AND type = 'income' -- Adjust or remove if 'type' is not used for revenue
                AND category IN ('Revenue', 'Sales Revenue')
                ${revenueDateFilter}
            GROUP BY month
            ORDER BY month;
        `, revenueQueryParams);

        // Fetch expenses from public.transactions by month with date filtering
        const expensesResult = await pool.query(`
            SELECT
                TO_CHAR(date, 'YYYY-MM') AS month,
                COALESCE(SUM(amount), 0) AS expenses
            FROM public.transactions
            WHERE
                type = 'expense'
                AND user_id = $1
                ${expenseDateFilter}
            GROUP BY month
            ORDER BY month;
        `, expenseQueryParams);

        // --- Data Aggregation and Transformation ---
        const revenueMap = new Map<string, { revenue: number, expenses: number }>();

        // Populate revenue from transactions
        revenueTransactionsResult.rows.forEach(row => {
            revenueMap.set(row.month, { revenue: parseFloat(row.revenue), expenses: 0 });
        });

        // Add expenses, or create new entry if only expenses exist for a month
        expensesResult.rows.forEach(row => {
            if (revenueMap.has(row.month)) {
                const existing = revenueMap.get(row.month)!;
                existing.expenses = parseFloat(row.expenses);
            } else {
                revenueMap.set(row.month, { revenue: 0, expenses: parseFloat(row.expenses) });
            }
        });

        // Calculate profit and format data for response
        const monthlyData: { month: string; profit: number; expenses: number; revenue: number }[] = [];
        const sortedMonths = Array.from(revenueMap.keys()).sort(); // Ensure data is sorted by month

        sortedMonths.forEach(month => {
            const data = revenueMap.get(month)!;
            const profit = data.revenue - data.expenses;
            monthlyData.push({
                month,
                profit: parseFloat(profit.toFixed(2)), // Format to 2 decimal places
                expenses: parseFloat(data.expenses.toFixed(2)),
                revenue: parseFloat(data.revenue.toFixed(2))
            });
        });

        // Send the aggregated and formatted monthly data as a JSON response
        res.json(monthlyData);
    } catch (error: unknown) {
        // Log the error and send a 500 internal server error response
        console.error('Error fetching revenue trend data:', error);
        res.status(500).json({
            error: 'Failed to fetch revenue trend data',
            detail: error instanceof Error ? error.message : String(error)
        });
    }
});




// GET Transaction Volume Data (Quotes, Invoices, Purchases by Month)
app.get('/api/charts/transaction-volume', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const { startDate, endDate } = req.query; // Extract startDate and endDate from query parameters

    try {
        let quotesDateFilter = '';
        let invoicesDateFilter = '';
        let purchasesDateFilter = '';

        const quotesQueryParams: (string | number)[] = [user_id];
        let quotesParamIndex = 2;
        if (startDate) {
            quotesDateFilter += ` AND created_at >= $${quotesParamIndex++}`;
            quotesQueryParams.push(startDate as string);
        }
        if (endDate) {
            quotesDateFilter += ` AND created_at <= $${quotesParamIndex++}`;
            quotesQueryParams.push(endDate as string);
        }

        const invoicesQueryParams: (string | number)[] = [user_id];
        let invoicesParamIndex = 2;
        if (startDate) {
            invoicesDateFilter += ` AND created_at >= $${invoicesParamIndex++}`;
            invoicesQueryParams.push(startDate as string);
        }
        if (endDate) {
            invoicesDateFilter += ` AND created_at <= $${invoicesParamIndex++}`;
            invoicesQueryParams.push(endDate as string);
        }

        const purchasesQueryParams: (string | number)[] = [user_id];
        let purchasesParamIndex = 2;
        if (startDate) {
            purchasesDateFilter += ` AND created_at >= $${purchasesParamIndex++}`;
            purchasesQueryParams.push(startDate as string);
        }
        if (endDate) {
            purchasesDateFilter += ` AND created_at <= $${purchasesParamIndex++}`;
            purchasesQueryParams.push(endDate as string);
        }

        // Fetch quotes count by month with date filtering
        const quotesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COUNT(id) AS count
            FROM public.quotations
            WHERE user_id = $1 ${quotesDateFilter}
            GROUP BY month
            ORDER BY month;
        `, quotesQueryParams);

        // Fetch invoices count by month with date filtering
        const invoicesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COUNT(id) AS count
            FROM public.invoices
            WHERE user_id = $1 ${invoicesDateFilter}
            GROUP BY month
            ORDER BY month;
        `, invoicesQueryParams);

        // Fetch purchases count by month with date filtering
        const purchasesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COUNT(id) AS count
            FROM public.purchases
            WHERE user_id = $1 ${purchasesDateFilter}
            GROUP BY month
            ORDER BY month;
        `, purchasesQueryParams);

        const monthlyMap = new Map<string, { quotes: number; invoices: number; purchases: number }>();

        quotesResult.rows.forEach(row => {
            monthlyMap.set(row.month, { quotes: parseInt(row.count, 10), invoices: 0, purchases: 0 });
        });
        purchasesResult.rows.forEach(row => {
            if (monthlyMap.has(row.month)) {
                monthlyMap.get(row.month)!.purchases = parseInt(row.count, 10);
            } else {
                monthlyMap.set(row.month, { quotes: 0, invoices: 0, purchases: parseInt(row.count, 10) });
            }
        });
        invoicesResult.rows.forEach(row => {
            if (monthlyMap.has(row.month)) {
                monthlyMap.get(row.month)!.invoices = parseInt(row.count, 10);
            } else {
                monthlyMap.set(row.month, { quotes: 0, invoices: parseInt(row.count, 10), purchases: 0 });
            }
        });

        const sortedMonths = Array.from(monthlyMap.keys()).sort();
        const monthlyData: { month: string; quotes: number; invoices: number; purchases: number }[] = [];

        sortedMonths.forEach(month => {
            monthlyData.push({
                month,
                quotes: monthlyMap.get(month)?.quotes || 0,
                invoices: monthlyMap.get(month)?.invoices || 0,
                purchases: monthlyMap.get(month)?.purchases || 0,
            });
        });

        res.json(monthlyData);
    } catch (error: unknown) {
        console.error('Error fetching transaction volume data:', error);
        res.status(500).json({ error: 'Failed to fetch transaction volume data', detail: error instanceof Error ? error.message : String(error) });
    }
});


// Upload endpoint
app.post('/documents', authMiddleware, upload.single('file'), async (req: Request, res: Response) => { // ADDED authMiddleware
    try {
        const file = req.file;
        const { name, type, description } = req.body; // Removed user_id from req.body
        const user_id = req.user!.parent_user_id; // Get user_id from req.user

        if (!file) return res.status(400).json({ error: 'No file uploaded' });

        // In a real application, you'd store the file securely (e.g., S3, Google Cloud Storage)
        // For this example, we're simulating a file URL.
        // You might need a more robust file storage solution.
        const fileUrl = `/uploads/${file.originalname}`; // Using originalname as a placeholder

        const mimeType = file.mimetype;
        const fileSize = file.size;

        const result = await pool.query(
            `INSERT INTO documents (user_id, name, type, description, file_url, file_mime_type, file_size_bytes)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [user_id, name, type, description, fileUrl, mimeType, fileSize]
        );

        res.status(201).json(result.rows[0]);
    } catch (error: unknown) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Something went wrong', detail: error instanceof Error ? error.message : String(error) });
    }
});

// (Optional) Get all documents
app.get('/documents', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query('SELECT * FROM documents WHERE user_id = $1 ORDER BY uploaded_at DESC', [user_id]); // ADDED user_id filter
        res.json(result.rows);
    } catch (error: unknown) {
        res.status(500).json({ error: 'Failed to fetch documents', detail: error instanceof Error ? error.message : String(error) });
    }
});

// Helper function to get status based on progress percentage
const getStatusFromPercentage = (percentage: number): string => {
    if (percentage === 100) {
        return 'Done';
    } else if (percentage >= 75) {
        return 'Review';
    } else if (percentage >= 25) {
        return 'In Progress';
    } else {
        return 'To Do';
    }
};

// After your pool + pool.query are defined
// Helper function to recompute task progress based on mode
// Helper function to recompute task progress based on mode
// Place this after your pool definition
// Helper function to recompute task progress based on mode
// Place this after your pool definition
async function recomputeTaskProgress(taskId: string) {
    // Fetch progress mode + goal/current
    const { rows: trows } = await pool.query(
        `SELECT progress_mode, progress_goal, progress_current
         FROM public.tasks WHERE id = $1`, [taskId]);
    if (!trows[0]) return;

    const { progress_mode, progress_goal, progress_current } = trows[0];

    let pct = 0;

    if (progress_mode === 'manual') {
        // keep whatever is already in progress_percentage (don't override)
        return;
    }

    if (progress_mode === 'target') { // Assuming 'target' is the correct mode name
        const goal = Math.max(Number(progress_goal || 0), 0);
        const cur = Math.max(Number(progress_current || 0), 0);
        pct = goal > 0 ? Math.min(100, Math.round((cur / goal) * 100)) : 0;
    }

    if (progress_mode === 'steps') { // Assuming 'steps' is the correct mode name
        const { rows: steps } = await pool.query(
            `SELECT weight, is_done FROM public.task_steps WHERE task_id = $1`, [taskId]);
        if (steps.length === 0) pct = 0;
        else {
            const hasWeights = steps.some(s => s.weight != null);
            if (hasWeights) {
                const totalW = steps.reduce((s, x) => s + Number(x.weight || 0), 0) || 0;
                const doneW = steps.filter(x => x.is_done).reduce((s, x) => s + Number(x.weight || 0), 0);
                pct = totalW > 0 ? Math.round((doneW / totalW) * 100) : 0;
            } else {
                const done = steps.filter(x => x.is_done).length;
                pct = Math.round((done / steps.length) * 100);
            }
        }
    }

    // --- CRITICAL FIX: Ensure parameters are in the CORRECT ORDER ---
    // The SQL string expects:
    // $1 = progress_percentage (NUMERIC) --> We pass 'pct' (the calculated number)
    // $2 = id (UUID)                   --> We pass 'taskId' (the UUID string)
    await pool.query(
        `UPDATE public.tasks SET progress_percentage = $1, updated_at = NOW() WHERE id = $2`,
        [pct, taskId] // <-- [NUMERIC VALUE, UUID STRING] - THIS ORDER IS CRUCIAL
    );
}
/* --- Task Management API Endpoints --- */

app.get('/api/tasks', authMiddleware, async (req: Request, res: Response) => {
    try {
        const currentUser_id = req.user!.user_id;       // The actual logged-in user's ID
        const parentUser_id = req.user!.parent_user_id; // The company owner's ID

        let query = `
            SELECT
                t.*,
                p.name AS project_name,
                u.name AS assignee_name, -- This line is supposed to get the name
                COALESCE(
                json_agg(
                    json_build_object(
                    'id', s.id,
                    'title', s.title,
                    'weight', s.weight,
                    'is_done', s.is_done,
                    'position', s.position
                    )
                    ORDER BY s.position ASC
                ) FILTER (WHERE s.id IS NOT NULL),
                '[]'::json
                ) AS steps
            FROM public.tasks t
            LEFT JOIN public.projects p ON p.id = t.project_id
            LEFT JOIN public.users u ON u.user_id = t.assignee_user_id -- This is the crucial join
            LEFT JOIN LATERAL (
                SELECT s.id, s.title, s.weight, s.is_done, s.position
                FROM public.task_steps s
                WHERE s.task_id = t.id
                ORDER BY s.position ASC
            ) s ON TRUE
        `;

        const queryParams: string[] = [];
        let paramIndex = 1;

        // Determine if the current user is the company owner
        const isCompanyOwner = currentUser_id === parentUser_id;

        if (isCompanyOwner) {
            // Company owners see all tasks associated with their company
            query += ` WHERE t.user_id = $${paramIndex++}::varchar`;
            queryParams.push(parentUser_id);
        } else {
            // Regular users only see tasks where they are explicitly assigned
            query += ` WHERE t.assignee_user_id = $${paramIndex++}::varchar`;
            queryParams.push(currentUser_id);
        }

        query += `
            GROUP BY t.id, p.name, u.name
            ORDER BY t.created_at DESC
        `;

        const { rows } = await pool.query(query, queryParams);
        res.json(rows);
    } catch (e: any) {
        console.error('list tasks error', e);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});



// POST /api/tasks - Create a new task
app.post('/api/tasks', authMiddleware, async (req: Request, res: Response) => {
    try {
        const user_id = req.user!.parent_user_id; // Use your existing pattern
        const {
            title, description, status, priority, due_date,
            progress_percentage, project_id, assignee_id,
            // New fields for target/step tracking
            progress_mode, progress_goal, progress_current
        } = req.body;

        // Optional validate: if assignee_id supplied, ensure it belongs to your company
        if (assignee_id) {
            const { rowCount } = await pool.query(
                `SELECT 1 FROM public.users WHERE id = $1 AND (parent_user_id = $2 OR user_id = $2)`,
                [assignee_id, user_id]
            );
            if (rowCount === 0) {
                return res.status(400).json({ error: 'Invalid assignee_id' });
            }
        }

        const insert = await pool.query(
            `
            INSERT INTO public.tasks
                (user_id, title, description, status, priority, due_date,
                progress_percentage, project_id, assignee_id,
                progress_mode, progress_goal, progress_current) -- Include new fields
            VALUES
                ($1, $2, $3, COALESCE($4,'To Do'), COALESCE($5,'Medium'), $6,
                COALESCE($7,0), $8, $9, $10, $11, $12) -- Include new field values
            RETURNING *
            `,
            [user_id, title, description, status, priority, due_date,
                progress_percentage, project_id || null, assignee_id || null,
                progress_mode || 'manual', progress_goal || null, progress_current || 0] // Default values for new fields
        );

        // Return with denormalized names and steps
        const { rows } = await pool.query(
            `
            SELECT
                t.*,
                p.name AS project_name,
                u.name AS assignee_name,
                COALESCE(
                json_agg(
                    json_build_object(
                    'id', s.id,
                    'title', s.title,
                    'weight', s.weight,
                    'is_done', s.is_done,
                    'position', s.position
                    )
                    ORDER BY s.position ASC
                ) FILTER (WHERE s.id IS NOT NULL),
                '[]'::json
                ) AS steps
            FROM public.tasks t
            LEFT JOIN public.projects p ON p.id = t.project_id
            LEFT JOIN public.users    u ON u.id = t.assignee_id
            LEFT JOIN public.task_steps s ON s.task_id = t.id
            WHERE t.id = $1
            GROUP BY t.id, p.name, u.name
            `,
            [insert.rows[0].id]
        );

        res.status(201).json(rows[0]);
    } catch (e: any) {
        console.error('create task error', e);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// PUT /api/tasks/:id - Update an existing task
// Consolidated and corrected version
app.put('/api/tasks/:id', authMiddleware, async (req: Request, res: Response) => {
    const taskId = req.params.id;
    const user_id = req.user!.parent_user_id; // Use your existing pattern

    const {
        title, description, priority, due_date, project_id, assignee_id,
        // Allow direct update of progress_percentage or mode-specific fields
        progress_percentage: clientProgress,
        progress_mode, progress_goal, progress_current,
        status: clientStatus // Allow client to explicitly set status if needed
    } = req.body;

    if (!title) {
        return res.status(400).json({ error: 'Task title is required.' });
    }

    try {
        // Make sure this task belongs to this user
        const { rowCount: exists } = await pool.query(
            `SELECT 1 FROM public.tasks WHERE id = $1 AND user_id = $2`,
            [taskId, user_id]
        );
        if (!exists) return res.status(404).json({ error: 'Task not found or unauthorized.' });

        // Validate assignee_id if provided
        if (assignee_id) {
            const { rowCount } = await pool.query(
                `SELECT 1 FROM public.users WHERE id = $1 AND (parent_user_id = $2 OR user_id = $2)`,
                [assignee_id, user_id]
            );
            if (rowCount === 0) {
                return res.status(400).json({ error: 'Invalid assignee_id' });
            }
        }

        // Determine status and progress
        let finalStatus = clientStatus;
        let finalProgress = typeof clientProgress === 'number' ? Math.max(0, Math.min(100, clientProgress)) : undefined;

        // If progress_percentage is explicitly set, derive status from it
        if (finalProgress !== undefined && !finalStatus) {
            finalStatus = getStatusFromPercentage(finalProgress);
        }

        // Build dynamic update query
        const updateFields = [];
        const updateValues = [];
        let paramIndex = 1;

        if (title !== undefined) {
            updateFields.push(`title = $${paramIndex}`);
            updateValues.push(title);
            paramIndex++;
        }
        if (description !== undefined) {
            updateFields.push(`description = $${paramIndex}`);
            updateValues.push(description);
            paramIndex++;
        }
        if (finalStatus !== undefined) {
            updateFields.push(`status = $${paramIndex}`);
            updateValues.push(finalStatus);
            paramIndex++;
        }
        if (priority !== undefined) {
            updateFields.push(`priority = $${paramIndex}`);
            updateValues.push(priority);
            paramIndex++;
        }
        if (due_date !== undefined) {
            updateFields.push(`due_date = $${paramIndex}`);
            updateValues.push(due_date);
            paramIndex++;
        }
        if (finalProgress !== undefined) {
            updateFields.push(`progress_percentage = $${paramIndex}`);
            updateValues.push(finalProgress);
            paramIndex++;
        }
        if (progress_mode !== undefined) {
            updateFields.push(`progress_mode = $${paramIndex}`);
            updateValues.push(progress_mode);
            paramIndex++;
        }
        if (progress_goal !== undefined) {
            updateFields.push(`progress_goal = $${paramIndex}`);
            updateValues.push(progress_goal);
            paramIndex++;
        }
        if (progress_current !== undefined) {
            updateFields.push(`progress_current = $${paramIndex}`);
            updateValues.push(progress_current);
            paramIndex++;
        }
        if (project_id !== undefined) {
            updateFields.push(`project_id = $${paramIndex}`);
            updateValues.push(project_id);
            paramIndex++;
        }
        if (assignee_id !== undefined) {
            updateFields.push(`assignee_id = $${paramIndex}`);
            updateValues.push(assignee_id);
            paramIndex++;
        }

        // Always update the timestamp
        updateFields.push(`updated_at = NOW()`);
        
        updateValues.push(taskId, user_id); // For WHERE clause

        if (updateFields.length > 1) { // Only if there are fields to update besides timestamp
            const updateQuery = `
                UPDATE public.tasks SET
                    ${updateFields.join(', ')}
                WHERE id = $${paramIndex - 1} AND user_id = $${paramIndex}
                RETURNING *`;
            
            await pool.query(updateQuery, updateValues);
        }

        // If mode-specific fields were updated, recalculate progress
        // Only recompute if mode is not manual, or if goal/current/mode changed
        if (progress_mode !== undefined || progress_goal !== undefined || progress_current !== undefined) {
             await recomputeTaskProgress(taskId);
        } else if (finalProgress !== undefined && progress_mode === 'manual') {
            // If manual mode and progress was explicitly set, no need to recompute
        } else if (progress_mode === 'manual') {
             // Explicitly manual mode, no action needed
        } else {
            // Recompute for other modes if no specific fields were changed but status/progress was
            await recomputeTaskProgress(taskId);
        }

        // Fetch and return the updated task with steps
        const { rows } = await pool.query(
            `
            SELECT
                t.*,
                p.name AS project_name,
                u.name AS assignee_name,
                COALESCE(
                json_agg(
                    json_build_object(
                    'id', s.id,
                    'title', s.title,
                    'weight', s.weight,
                    'is_done', s.is_done,
                    'position', s.position
                    )
                    ORDER BY s.position ASC
                ) FILTER (WHERE s.id IS NOT NULL),
                '[]'::json
                ) AS steps
            FROM public.tasks t
            LEFT JOIN public.projects p ON p.id = t.project_id
            LEFT JOIN public.users    u ON u.id = t.assignee_id
            LEFT JOIN public.task_steps s ON s.task_id = t.id
            WHERE t.id = $1
            GROUP BY t.id, p.name, u.name
            `,
            [taskId]
        );

        res.json(rows[0]);
    } catch (error: unknown) {
        console.error('Error updating task:', error);
        res.status(500).json({ error: 'Failed to update task.', detail: error instanceof Error ? error.message : String(error) });
    }
});

// DELETE /api/tasks/:id - Delete a task
app.delete('/api/tasks/:id', authMiddleware, async (req: Request, res: Response) => {
    const taskId = req.params.id;
    const user_id = req.user!.parent_user_id; // Use your existing pattern

    try {
        const result = await pool.query(
            `DELETE FROM public.tasks WHERE id = $1 AND user_id = $2 RETURNING id`,
            [taskId, user_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Task not found or unauthorized.' });
        }
        res.status(204).send(); // No Content
    } catch (error: unknown) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Failed to delete task.', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PATCH /api/tasks/:id/assign
app.patch('/api/tasks/:id/assign', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Use your existing pattern
    const taskId = req.params.id;
    const { assignee_id } = req.body;

    if (!assignee_id) return res.status(400).json({ error: 'assignee_id is required' });

    // Validate assignee_id
    const { rowCount } = await pool.query(
        `SELECT 1 FROM public.users WHERE id = $1 AND (parent_user_id = $2 OR user_id = $2)`,
        [assignee_id, user_id]
    );
    if (rowCount === 0) {
        return res.status(400).json({ error: 'Invalid assignee_id' });
    }

    await pool.query(
        `UPDATE public.tasks SET assignee_id = $3, updated_at = NOW()
         WHERE id = $1 AND user_id = $2`,
        [taskId, user_id, assignee_id]
    );
    res.json({ ok: true });
});

// PATCH /api/tasks/:id/unassign
app.patch('/api/tasks/:id/unassign', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Use your existing pattern
    const taskId = req.params.id;

    await pool.query(
        `UPDATE public.tasks SET assignee_id = NULL, updated_at = NOW()
         WHERE id = $1 AND user_id = $2`,
        [taskId, user_id]
    );
    res.json({ ok: true });
});

// POST /api/tasks/:id/progress/increment (for target mode)
app.post('/api/tasks/:id/progress/increment', authMiddleware, async (req, res) => {
    const taskId = req.params.id;
    const user_id = req.user!.parent_user_id; // Use your existing pattern

    try {
        // Ensure task belongs to user
        const taskCheck = await pool.query(
            `SELECT 1 FROM public.tasks WHERE id = $1 AND user_id = $2`,
            [taskId, user_id]
        );
        if (taskCheck.rowCount === 0) {
             return res.status(404).json({ error: 'Task not found or unauthorized.' });
        }

        // Increment current progress
        await pool.query(`
            UPDATE public.tasks
            SET progress_current = LEAST(COALESCE(progress_goal, 2147483647),
                                         COALESCE(progress_current, 0) + 1),
                updated_at = NOW()
            WHERE id = $1`,
            [taskId]
        );
        
        // Recalculate progress percentage based on mode
        await recomputeTaskProgress(taskId);

        // Fetch and return the updated task
        const { rows } = await pool.query(
            `
            SELECT
                t.*,
                p.name AS project_name,
                u.name AS assignee_name,
                COALESCE(
                json_agg(
                    json_build_object(
                    'id', s.id,
                    'title', s.title,
                    'weight', s.weight,
                    'is_done', s.is_done,
                    'position', s.position
                    )
                    ORDER BY s.position ASC
                ) FILTER (WHERE s.id IS NOT NULL),
                '[]'::json
                ) AS steps
            FROM public.tasks t
            LEFT JOIN public.projects p ON p.id = t.project_id
            LEFT JOIN public.users    u ON u.id = t.assignee_id
            LEFT JOIN public.task_steps s ON s.task_id = t.id
            WHERE t.id = $1
            GROUP BY t.id, p.name, u.name
            `,
            [taskId]
        );

        res.json(rows[0]);
    } catch (error: unknown) {
        console.error('Error incrementing task progress:', error);
        res.status(500).json({ error: 'Failed to increment task progress.', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT /api/tasks/:id/progress - Dedicated endpoint for updating progress/targets/steps
// PUT /api/tasks/:id/progress - Dedicated endpoint for updating progress/targets/steps
app.put('/api/tasks/:id/progress', authMiddleware, async (req, res) => {
    const taskId = req.params.id;
    const user_id = req.user!.parent_user_id; // Use your existing pattern
    const {
        progress_mode,
        progress_goal,
        progress_current,
        steps // Array of step updates/creates
    } = req.body;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Ensure task belongs to user
        const taskCheck = await client.query(
            `SELECT progress_mode FROM public.tasks WHERE id = $1 AND user_id = $2`,
            [taskId, user_id]
        );
        if (taskCheck.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Task not found or unauthorized.' });
        }
        const currentTaskMode = taskCheck.rows[0].progress_mode;

        // --- UPDATE TASK PROGRESS FIELDS ---
        const updateFields = [];
        const updateValues = [];
        let paramIndex = 1; // Start parameter indexing

        if (progress_mode !== undefined) {
            updateFields.push(`progress_mode = $${paramIndex}`);
            updateValues.push(progress_mode);
            paramIndex++;
        }

        if (progress_goal !== undefined) {
            updateFields.push(`progress_goal = $${paramIndex}`);
            updateValues.push(progress_goal);
            paramIndex++;
        }

        if (progress_current !== undefined) {
            updateFields.push(`progress_current = $${paramIndex}`);
            updateValues.push(progress_current);
            paramIndex++;
        }

        // Calculate and set progress_percentage if in 'target' mode
        let calculatedProgress: number | null = null;
        const newMode = progress_mode !== undefined ? progress_mode : currentTaskMode;
        if (newMode === 'target' && progress_goal !== undefined) {
            const goal = Math.max(Number(progress_goal || 0), 0);
            const currentVal = Math.max(Number(progress_current !== undefined ? progress_current : (taskCheck.rows[0].progress_current || 0)), 0);
            calculatedProgress = goal > 0 ? Math.min(100, Math.round((currentVal / goal) * 100)) : 0;
            updateFields.push(`progress_percentage = $${paramIndex}`);
            updateValues.push(calculatedProgress); // Push the NUMBER first
            paramIndex++;
        }

        // Always update the timestamp
        updateFields.push('updated_at = NOW()');

        // --- CRITICAL: Push UUIDs LAST and use placeholders correctly ---
        // Add placeholders for WHERE clause parameters
        const whereIdPlaceholder = `$${paramIndex}`;
        const whereUserIdPlaceholder = `$${paramIndex + 1}`;
        // Push UUID values LAST into the array
        updateValues.push(taskId, user_id);

        // If there are fields to update (beyond just updated_at), run the query
        if (updateFields.length > 1) {
            const updateQuery = `
                UPDATE public.tasks SET
                    ${updateFields.join(', ')}
                WHERE id = ${whereIdPlaceholder} AND user_id = ${whereUserIdPlaceholder}`;

            await client.query(updateQuery, updateValues);
        }
        // --- END UPDATE TASK ---

        // --- HANDLE STEPS ---
        // Handle steps if provided
        if (steps && Array.isArray(steps)) {
            for (const step of steps) {
                if (step.id) {
                    // Update existing step
                    await client.query(`
                        UPDATE public.task_steps SET
                            title = COALESCE($1, title),
                            weight = COALESCE($2, weight),
                            is_done = COALESCE($3, is_done),
                            position = COALESCE($4, position)
                        WHERE id = $5 AND task_id = $6`,
                        [step.title, step.weight, step.is_done, step.position, step.id, taskId]
                    );
                } else {
                    // Create new step
                    await client.query(`
                        INSERT INTO public.task_steps (task_id, title, weight, is_done, position)
                        VALUES ($1, $2, $3, $4, $5)`,
                        [taskId, step.title, step.weight || 1, step.is_done || false, step.position || 0]
                    );
                }
            }
        }

        // If in 'steps' mode, recalculate progress based on steps
        if (newMode === 'steps') {
            const stepResult = await client.query(
                'SELECT weight, is_done FROM public.task_steps WHERE task_id = $1',
                [taskId]
            );

            const stepsData = stepResult.rows;
            if (stepsData.length > 0) {
                const totalWeight = stepsData.reduce((sum, step) => sum + (step.weight || 0), 0);
                const completedWeight = stepsData
                    .filter(step => step.is_done)
                    .reduce((sum, step) => sum + (step.weight || 0), 0);

                const stepProgress = totalWeight > 0
                    ? Math.round((completedWeight / totalWeight) * 100)
                    : 0;

                // --- CORRECTED: Parameter order for steps mode update ---
                await client.query(
                    'UPDATE public.tasks SET progress_percentage = $1, updated_at = NOW() WHERE id = $2',
                    [stepProgress, taskId] // [NUMBER, UUID] - Correct order
                );
                // --- END CORRECTED ---
            } else {
                 // If no steps, progress is 0
                 await client.query(
                    'UPDATE public.tasks SET progress_percentage = $1, updated_at = NOW() WHERE id = $2',
                    [0, taskId]
                );
            }
        }
        // --- END HANDLE STEPS ---

        await client.query('COMMIT');

        // Return updated task with steps
        const { rows } = await pool.query(
            `
            SELECT
                t.*,
                p.name AS project_name,
                u.name AS assignee_name,
                COALESCE(
                json_agg(
                    json_build_object(
                    'id', s.id,
                    'title', s.title,
                    'weight', s.weight,
                    'is_done', s.is_done,
                    'position', s.position
                    )
                    ORDER BY s.position ASC
                ) FILTER (WHERE s.id IS NOT NULL),
                '[]'::json
                ) AS steps
            FROM public.tasks t
            LEFT JOIN public.projects p ON p.id = t.project_id
            LEFT JOIN public.users    u ON u.id = t.assignee_id
            LEFT JOIN public.task_steps s ON s.task_id = t.id
            WHERE t.id = $1
            GROUP BY t.id, p.name, u.name`,
            [taskId]
        );

        res.json(rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error updating task progress:', error);
        // Provide a more specific error message if it's the type mismatch we've been fixing
        if (error instanceof Error && error.message.includes('progress_percentage') && error.message.includes('uuid')) {
             res.status(500).json({ error: 'Failed to update task progress due to a data type mismatch. Please check server logs.' });
        } else {
             res.status(500).json({ error: 'Failed to update task progress' });
        }
    } finally {
        client.release();
    }
});

// --- Task Steps API Endpoints ---

// POST /api/tasks/:taskId/steps - Create a new step for a task
app.post('/api/tasks/:taskId/steps', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Use your existing pattern
    const { taskId } = req.params;
    const { title, weight, is_done, position } = req.body;

    if (!title) {
        return res.status(400).json({ error: 'Step title is required.' });
    }

    try {
        // Verify task belongs to user
        const taskCheck = await pool.query(
            'SELECT 1 FROM public.tasks WHERE id = $1 AND user_id = $2',
            [taskId, user_id]
        );

        if (taskCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Task not found or unauthorized' });
        }

        const result = await pool.query(`
            INSERT INTO public.task_steps (task_id, title, weight, is_done, position)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *`,
            [taskId, title, weight || 1, is_done || false, position || 0]
        );

        // Recalculate task progress if task is in 'steps' mode
        await recomputeTaskProgress(taskId);

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating step:', error);
        res.status(500).json({ error: 'Failed to create step' });
    }
});

// PUT /api/steps/:stepId - Update a step
app.put('/api/steps/:stepId', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Use your existing pattern
    const { stepId } = req.params;
    const { title, weight, is_done, position } = req.body;

    try {
        // Verify step belongs to user's task
        const stepCheck = await pool.query(`
            SELECT 1 FROM public.task_steps ts
            JOIN public.tasks t ON ts.task_id = t.id
            WHERE ts.id = $1 AND t.user_id = $2`,
            [stepId, user_id]
        );

        if (stepCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Step not found or unauthorized' });
        }

        const result = await pool.query(`
            UPDATE public.task_steps SET
                title = COALESCE($1, title),
                weight = COALESCE($2, weight),
                is_done = COALESCE($3, is_done),
                position = COALESCE($4, position)
            WHERE id = $5
            RETURNING *`,
            [title, weight, is_done, position, stepId]
        );

        // Get task_id for progress recalculation
        const taskResult = await pool.query(
            'SELECT task_id FROM public.task_steps WHERE id = $1',
            [stepId]
        );

        if (taskResult.rows.length > 0) {
            await recomputeTaskProgress(taskResult.rows[0].task_id);
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating step:', error);
        res.status(500).json({ error: 'Failed to update step' });
    }
});

// DELETE /api/steps/:stepId - Delete a step
app.delete('/api/steps/:stepId', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Use your existing pattern
    const { stepId } = req.params;

    try {
        // Verify step belongs to user's task and get task_id
        const stepCheck = await pool.query(`
            SELECT ts.task_id FROM public.task_steps ts
            JOIN public.tasks t ON ts.task_id = t.id
            WHERE ts.id = $1 AND t.user_id = $2`,
            [stepId, user_id]
        );

        if (stepCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Step not found or unauthorized' });
        }

        const taskId = stepCheck.rows[0].task_id;

        await pool.query('DELETE FROM public.task_steps WHERE id = $1', [stepId]);

        // Recalculate task progress
        await recomputeTaskProgress(taskId);

        res.json({ message: 'Step deleted successfully' });
    } catch (error) {
        console.error('Error deleting step:', error);
        res.status(500).json({ error: 'Failed to delete step' });
    }
});
/* --- Project Management API Endpoints --- */

// POST /api/projects - Create a new project
app.post('/api/projects', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { name, description, deadline, status, assignee, progress_percentage } = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!name) {
        return res.status(400).json({ error: 'Project name is required.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO public.projects (user_id, name, description, deadline, status, assignee, progress_percentage, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW()) RETURNING *`, // ADDED user_id
            [
                user_id, // ADDED user_id
                name,
                description || null,
                deadline || null,
                status || 'Not Started',
                assignee || null,
                progress_percentage || 0.00
            ]
        );
        res.status(201).json(result.rows[0]);
    } catch (error: unknown) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project.', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET /api/projects - Fetch all projects
app.get('/api/projects', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query(
            `SELECT id, name, description, deadline, status, assignee, progress_percentage, created_at, updated_at
             FROM public.projects WHERE user_id = $1 ORDER BY created_at DESC`, // ADDED user_id filter
            [user_id]
        );
        res.json(result.rows);
    } catch (error: unknown) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects.', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT /api/projects/:id - Update an existing project
app.put('/api/projects/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    const { name, description, deadline, status, assignee, progress_percentage } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Project name is required.' });
    }

    try {
        const result = await pool.query(
            `UPDATE public.projects
             SET name = $1, description = $2, deadline = $3, status = $4, assignee = $5, progress_percentage = $6, updated_at = NOW()
             WHERE id = $7 AND user_id = $8 RETURNING *`, // ADDED user_id filter
            [
                name,
                description || null,
                deadline || null,
                status || 'Not Started',
                assignee || null,
                progress_percentage || 0.00,
                id,
                user_id // ADDED user_id
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found or unauthorized.' });
        }
        res.json(result.rows[0]);
    } catch (error: unknown) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project.', detail: error instanceof Error ? error.message : String(error) });
    }
});

// DELETE /api/projects/:id - Delete a project
app.delete('/api/projects/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    try {
        const result = await pool.query(
            `DELETE FROM public.projects WHERE id = $1 AND user_id = $2 RETURNING id`, // ADDED user_id filter
            [id, user_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found or unauthorized.' });
        }
        res.status(204).send(); // No Content
    } catch (error: unknown) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: 'Failed to delete project.', detail: error instanceof Error ? error.message : String(error) });
    }
});

/* --- Financial Document Generation API (dual: JSON or PDF) --- */
/* --- Financial Document Generation API (dual: JSON or PDF) --- */
/* --- Financial Document Generation API (dual: JSON or PDF) --- */
/* --- Financial Document Generation API (dual: JSON or PDF) --- */
// server.ts

// Make sure you have these imports at the top
// import puppeteer from 'puppeteer';
// import path from 'path';

// Helper function to format currency


// Helper function to format date
// server.ts


// You might also need 'path' if you use it elsewhere

// --- Helper Functions (Place these outside the endpoint if they aren't already globally available) ---


const formatDate = (dateStr: string): string => {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-ZA', { year: 'numeric', month: 'long', day: 'numeric' });
};
// --- End Helper Functions ---

// Helper function to format date


// Make sure you have these imports at the top of your file
// import PDFDocument from 'pdfkit';
// import { authMiddleware } from './middleware/auth'; // Adjust path as needed
// import axios from 'axios'; // Needed if you want to fetch the logo via URL like in quotations

app.get('/generate-financial-document', authMiddleware, async (req: Request, res: Response) => {
    const { documentType, startDate, endDate, format: formatParam } = req.query as {
        documentType?: string;
        startDate?: string;
        endDate?: string;
        format?: string; // 'json' to return data
    };

    if (!documentType || !startDate || !endDate) {
        return res.status(400).json({ error: 'documentType, startDate, and endDate are required.' });
    }

    // Scope to the company owner (tenant)
    const user_id = req.user!.parent_user_id;
    const wantJson = String(formatParam || '').toLowerCase() === 'json';

    try {
        let filename = '';

        // --- Determine the Filename based on documentType ---
        switch (documentType) {
            case 'income-statement':
                filename = `Income_Statement_${startDate}_to_${endDate}.pdf`;
                break;
            case 'balance-sheet':
                filename = `Balance_Sheet_As_Of_${endDate}.pdf`;
                break;
            case 'cash-flow-statement':
                filename = `Cash_Flow_Statement_${startDate}_to_${endDate}.pdf`;
                break;
            case 'trial-balance':
                filename = `Trial_Balance_${startDate}_to_${endDate}.pdf`;
                break;
            default:
                return res.status(400).json({ error: `Unsupported document type: ${documentType}` });
        }
        // --- End Filename Determination ---

        // --- Fetch Company Details (Like in quotations/invoices) ---
        const userProfileResult = await pool.query(
            `SELECT company, address, city, province, postal_code, country, phone, email, company_logo_path
             FROM users WHERE user_id = $1`,
            [user_id]
        );
        const userCompany = userProfileResult.rows[0];
        const companyName = userCompany?.company || 'Your Company';
        // Dynamically construct the full company address string
        const companyFullAddressParts = [
            userCompany?.address,
            userCompany?.city,
            userCompany?.province,
            userCompany?.postal_code,
            userCompany?.country
        ].filter(part => part); // Remove falsy values
        const companyFullAddress = companyFullAddressParts.length > 0 ? companyFullAddressParts.join(', ') : null;

        const companyPhone = userCompany?.phone || null;
        const companyEmail = userCompany?.email || null;
        const companyVat = userCompany?.vat_number || null;
        const companyReg = userCompany?.reg_number || null;

        let companyLogoBuffer: Buffer | null = null;
        if (userCompany?.company_logo_path) {
            try {
                // 1. Get the public URL from Supabase Storage
                const { data } = supabase.storage.from('company-logos').getPublicUrl(userCompany.company_logo_path);
                const companyLogoUrl = data.publicUrl;
                console.log(`[DEBUG] Generated logo URL: ${companyLogoUrl}`);

                // 2. Fetch the image data from the public URL using axios
                // Ensure responseType is 'arraybuffer' for binary data
                const logoResponse = await axios.get(companyLogoUrl, { responseType: 'arraybuffer' });
                companyLogoBuffer = Buffer.from(logoResponse.data, 'binary'); // Convert to Buffer
                console.log(`[DEBUG] Fetched logo buffer, size: ${companyLogoBuffer?.length} bytes`);
            } catch (logoFetchError) {
                // 3. Handle errors during fetching or conversion
                console.warn(`[WARN] Failed to fetch or process logo from URL ${userCompany.company_logo_path}:`, logoFetchError);
                // companyLogoBuffer remains null, so the logo will be skipped in the PDF
            }
        }


        // --- INTERNAL API CALL to fetch the raw JSON data ---
        let reportData: any = null;

        if (documentType === 'income-statement') {
            const userId = user_id;
            const start = startDate!;
            const end = endDate!;
            const { rows } = await pool.query(
                `SELECT
                    a.name AS account_name,
                    rc.section AS reporting_section,
                    a.normal_side AS normal_side,
                    SUM(jl.debit - jl.credit) AS balance
                FROM
                    public.journal_lines jl
                JOIN
                    public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                JOIN
                    public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                JOIN
                    public.reporting_categories rc ON rc.id = a.reporting_category_id
                WHERE
                    je.user_id = $1
                    AND rc.statement = 'income_statement'
                    AND je.entry_date BETWEEN $2::date AND $3::date
                GROUP BY
                    a.name, rc.section, a.normal_side
                ORDER BY
                    rc.section, a.name;`,
                [userId, start, end]
            );

            const sectionMap: Record<string, { section: string; amount: number; accounts: any[] }> = {};

            rows.forEach(row => {
                const sectionName = row.reporting_section;
                if (!sectionMap[sectionName]) {
                    sectionMap[sectionName] = {
                        section: sectionName,
                        amount: 0,
                        accounts: []
                    };
                }

                const balance = parseFloat(row.balance);
                // Adjust sign based on normal side for Income Statement logic
                const amount = (row.normal_side === 'Credit') ? -balance : balance;

                sectionMap[sectionName].amount += amount;
                sectionMap[sectionName].accounts.push({
                    name: row.account_name,
                    amount: amount
                });
            });

            reportData = { period: { start, end }, sections: Object.values(sectionMap) };
        }
        else if (documentType === 'balance-sheet') {
            const userId = user_id;
            const asOf = endDate!; // Use endDate as the "as of" date
            const client = await pool.connect();
            try {
                const profitLossResult = await client.query(
                    `
                    SELECT
                        SUM(CASE
                            WHEN a.normal_side = 'Credit' THEN (jl.credit - jl.debit) -- Revenue/Income
                            ELSE -(jl.debit - jl.credit) -- Expenses (negate to subtract from income)
                        END) AS net_profit_loss
                    FROM public.journal_lines jl
                    JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                    JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                    JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
                    WHERE je.user_id = $1
                        AND rc.statement = 'income_statement'
                        AND je.entry_date <= $2::date
                    `,
                    [userId, asOf]
                );
                const netProfitLoss = parseFloat(profitLossResult.rows[0]?.net_profit_loss) || 0;

                const { rows: balanceSheetSections } = await client.query(
                    `
                    SELECT rc.section,
                        SUM(CASE a.normal_side
                                WHEN 'Debit' THEN (jl.debit - jl.credit)
                                ELSE -(jl.debit - jl.credit)
                            END) AS value
                        FROM public.journal_lines jl
                        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                        JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
                        WHERE je.user_id = $1
                        AND rc.statement = 'balance_sheet'
                        AND je.entry_date <= $2::date
                        GROUP BY rc.section
                        ORDER BY rc.section
                    `,
                    [userId, asOf]
                );

                const obeAccountResult = await client.query(
                    `SELECT id FROM public.accounts WHERE user_id = $1 AND name = 'Opening Balance Equity' LIMIT 1`,
                    [userId]
                );
                let openingBalanceEquityValue = 0;
                if (obeAccountResult.rows.length > 0) {
                    const obeAccountId = obeAccountResult.rows[0].id;
                    const obeBalanceResult = await client.query(
                        `
                        SELECT
                        SUM(CASE a.normal_side
                                WHEN 'Debit' THEN (jl.debit - jl.credit)
                                ELSE -(jl.debit - jl.credit)
                            END) AS balance
                        FROM public.journal_lines jl
                        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                        WHERE jl.user_id = $1
                            AND jl.account_id = $2
                            AND je.entry_date <= $3::date
                        `,
                        [userId, obeAccountId, asOf]
                    );
                    openingBalanceEquityValue = parseFloat(obeBalanceResult.rows[0]?.balance) || 0;
                }

                const sectionsMap: Record<string, number> = {};
                balanceSheetSections.forEach(s => {
                    sectionsMap[s.section] = parseFloat(s.value) || 0;
                });

                const closingEquity = openingBalanceEquityValue + netProfitLoss;

                reportData = {
                    asOf,
                    sections: balanceSheetSections,
                    openingEquity: openingBalanceEquityValue,
                    netProfitLoss: netProfitLoss,
                    closingEquity: closingEquity,
                    assets: {
                        current: sectionsMap['current_assets'] || 0,
                        non_current: sectionsMap['non_current_assets'] || 0
                    },
                    liabilities: {
                        current: sectionsMap['current_liabilities'] || 0,
                        non_current: sectionsMap['non_current_liabilities'] || 0
                    }
                };
            } finally {
                client.release();
            }
        }
        else if (documentType === 'cash-flow-statement') {
            const userId = user_id;
            const start = startDate!;
            const end = endDate!;
            const { rows } = await pool.query(
                `
                WITH cash_changes AS (
                SELECT
                    'operating' as section,
                    'Net Income' as line,
                    SUM(CASE
                        WHEN a.normal_side = 'Credit' THEN (jl.credit - jl.debit)
                        ELSE (jl.debit - jl.credit)
                    END) as amount
                FROM public.journal_lines jl
                JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
                WHERE je.user_id = $1
                    AND rc.statement = 'income_statement'
                    AND je.entry_date BETWEEN $2::date AND $3::date

                UNION ALL

                SELECT
                    'operating' as section,
                    'Depreciation' as line,
                    SUM(CASE
                        WHEN a.normal_side = 'Debit' THEN (jl.debit - jl.credit)
                        ELSE (jl.credit - jl.debit)
                    END) as amount
                FROM public.journal_lines jl
                JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                WHERE je.user_id = $1
                    AND a.name ILIKE '%depreciation%'
                    AND je.entry_date BETWEEN $2::date AND $3::date

                UNION ALL

                SELECT
                    'investing' as section,
                    'Purchase of Assets' as line,
                    SUM(CASE
                        WHEN a.normal_side = 'Debit' THEN (jl.debit - jl.credit)
                        ELSE (jl.credit - jl.debit)
                    END) as amount
                FROM public.journal_lines jl
                JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                WHERE je.user_id = $1
                    AND a.type = 'Asset'
                    AND je.entry_date BETWEEN $2::date AND $3::date

                UNION ALL

                SELECT
                    'financing' as section,
                    'Loan Proceeds' as line,
                    SUM(CASE
                        WHEN a.normal_side = 'Credit' THEN (jl.credit - jl.debit)
                        ELSE (jl.debit - jl.credit)
                    END) as amount
                FROM public.journal_lines jl
                JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
                JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
                WHERE je.user_id = $1
                    AND a.type = 'Liability'
                    AND je.entry_date BETWEEN $2::date AND $3::date
                )

                SELECT section, line, COALESCE(amount, 0) as amount
                FROM cash_changes
                WHERE amount != 0
                ORDER BY section, line
                `,
                [userId, start, end]
            );

            const grouped: Record<string, { line: string; amount: string | number }[]> = {};
            for (const r of rows) {
                grouped[r.section] = grouped[r.section] || [];
                grouped[r.section].push({ line: r.line, amount: parseFloat(r.amount.toString()) });
            }

            reportData = { period: { start, end }, sections: grouped };
        }
        else if (documentType === 'trial-balance') {
            const userId = user_id;
            const start = startDate!;
            const end = endDate!;
            const includeZero = false; // Match default behavior of endpoint

            const { rows } = await pool.query(
                `
                WITH period AS (
                SELECT
                    a.id AS account_id,
                    a.code,
                    a.name,
                    a.type,
                    COALESCE(SUM(jl.debit), 0)::numeric(18,2) AS total_debit,
                    COALESCE(SUM(jl.credit), 0)::numeric(18,2) AS total_credit
                FROM public.accounts a
                LEFT JOIN public.journal_lines jl
                    ON jl.account_id = a.id
                    AND jl.user_id = a.user_id
                LEFT JOIN public.journal_entries je
                    ON je.id = jl.entry_id
                    AND je.user_id = jl.user_id
                WHERE a.user_id = $1
                    AND (je.entry_date BETWEEN $2::date AND $3::date OR je.entry_date IS NULL)
                GROUP BY a.id, a.code, a.name, a.type
                )
                SELECT
                account_id, code, name, type,
                total_debit,
                total_credit,
                GREATEST(total_debit - total_credit, 0)::numeric(18,2) AS balance_debit,
                GREATEST(total_credit - total_debit, 0)::numeric(18,2) AS balance_credit
                FROM period
                ORDER BY code::text, name::text;
                `,
                [userId, start, end]
            );

            const items = includeZero
                ? rows
                : rows.filter(r =>
                    Number(r.total_debit) !== 0 ||
                    Number(r.total_credit) !== 0 ||
                    Number(r.balance_debit) !== 0 ||
                    Number(r.balance_credit) !== 0
                );

            const totals = items.reduce(
                (t, r) => {
                    t.total_debit += Number(r.total_debit);
                    t.total_credit += Number(r.total_credit);
                    t.balance_debit += Number(r.balance_debit);
                    t.balance_credit += Number(r.balance_credit);
                    return t;
                },
                { total_debit: 0, total_credit: 0, balance_debit: 0, balance_credit: 0 }
            );

            reportData = {
                period: { start, end },
                totals,
                items
            };
        }
        // --- END INTERNAL API CALL SIMULATION ---

        if (wantJson) {
            return res.json(reportData);
        }

        // --- Generate PDF using PDFKit ---
        const doc = new PDFDocument({ size: 'A4', margin: 50 });
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));

        doc.on('end', () => {
            const pdfBuffer = Buffer.concat(chunks);
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
            res.send(pdfBuffer);
        });

        doc.on('error', (err: Error) => {
            console.error('Error generating PDF with PDFKit:', err);
            if (!res.headersSent) {
                return res.status(500).json({
                    error: 'Failed to generate PDF document with PDFKit',
                    detail: err.message || String(err)
                });
            } else {
                console.error('Headers already sent. Could not send JSON error response.');
            }
        });

        // --- Draw Header with Company Info and Logo ---
        const drawHeader = () => {
            const top = 70;
            const rightAlign = doc.page.width - 50;
            let y = top;
            const logoMaxWidth = 100; // Maximum width for the logo
            const logoMaxHeight = 50; // Maximum height for the logo

            // Add Logo (if exists and buffer is valid)
            if (companyLogoBuffer) {
                try {
                    // Use the 'fit' option to scale the image proportionally within the specified dimensions
                    doc.image(companyLogoBuffer, rightAlign - logoMaxWidth, top, {
                        fit: [logoMaxWidth, logoMaxHeight],
                        align: 'right',
                        valign: 'top'
                    });
                    console.log("[DEBUG] Logo added to PDF from buffer");
                } catch (logoDrawError) {
                    console.warn(`[WARN] Failed to draw logo buffer to PDF:`, logoDrawError);
                    // Continue without logo if drawing fails
                }
            }

            // Add Company Info (aligned to the left)
            doc.fontSize(16).font('Helvetica-Bold').text(companyName, 50, y); // Align left
            y += 20;
            if (companyFullAddress) {
                doc.fontSize(10).font('Helvetica').text(companyFullAddress, 50, y);
                y += 15;
            }
            // Optional: Add Phone, Email, VAT, Reg if desired
            const contactInfoParts = [];
            if (companyPhone) contactInfoParts.push(`Phone: ${companyPhone}`);
            if (companyEmail) contactInfoParts.push(`Email: ${companyEmail}`);
            if (contactInfoParts.length > 0) {
                doc.fontSize(10).text(contactInfoParts.join(' | '), 50, y);
                y += 15;
            }
            if (companyVat) {
                doc.fontSize(10).text(`VAT: ${companyVat}`, 50, y);
                y += 15;
            }
            if (companyReg) {
                doc.fontSize(10).text(`Reg: ${companyReg}`, 50, y);
                y += 15;
            }

            // Draw a line separator
            doc.moveTo(50, y).lineTo(rightAlign, y).stroke();
            doc.moveDown(1); // Add space after header
        };

        // Call the drawHeader function only for the first page
        drawHeader();

        // --- Add Content to PDF based on documentType ---
        if (documentType === 'income-statement') {
            doc.fontSize(18).font('Helvetica-Bold').text('Income Statement', { align: 'center' });
            doc.fontSize(12).font('Helvetica').text(`For the period ${formatDate(reportData.period.start)} to ${formatDate(reportData.period.end)}`, { align: 'center' });
            doc.moveDown();

            const sectionsToPrint = [
                { id: 'revenue', title: 'Revenue' },
                { id: 'other_income', title: 'Other Income' },
                { id: 'cost_of_goods_sold', title: 'Cost of Goods Sold' },
                { id: 'operating_expenses', title: 'Operating Expenses' },
                { id: 'other_expenses', title: 'Other Expenses' },
            ];

            // Re-calculate totals more explicitly for clarity
            let totalRevenue = 0;
            let totalExpenses = 0;

            sectionsToPrint.forEach(sectionMeta => {
                const sectionData = reportData.sections.find((s: any) => s.section === sectionMeta.id);

                if (sectionData) {
                    doc.fontSize(14).font('Helvetica-Bold').text(sectionMeta.title).moveDown(0.5);

                    sectionData.accounts.forEach((account: any) => {
                        doc.fontSize(12).font('Helvetica').text(`  ${account.name}`).text(formatCurrency(account.amount), { align: 'right' });
                    });

                    // Add to appropriate total (expenses are already negative in calculation)
                    if (['revenue', 'other_income'].includes(sectionMeta.id)) {
                        totalRevenue += sectionData.amount;
                    } else {
                        totalExpenses += sectionData.amount;
                    }

                    doc.moveDown(0.5);
                    const subtotalLabel = `Total ${sectionMeta.title}`;
                    doc.fontSize(12).font('Helvetica').text(subtotalLabel).text(formatCurrency(sectionData.amount), { align: 'right' }).moveDown();
                }
            });

            // The net profit is the total revenue minus the total expenses
            const netProfitLoss = totalRevenue - totalExpenses; // Expenses are negative, so subtraction adds them correctly

            doc.moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).stroke().moveDown(0.5);
            doc.fontSize(14).font('Helvetica-Bold').text(`${netProfitLoss >= 0 ? 'NET PROFIT for the period' : 'NET LOSS for the period'}`).text(formatCurrency(Math.abs(netProfitLoss)), { align: 'right' });
        }
        else if (documentType === 'balance-sheet') {
            const totalAssets = (reportData.assets.current || 0) + (reportData.assets.non_current || 0);
            const totalLiabilities = (reportData.liabilities.current || 0) + (reportData.liabilities.non_current || 0);
            const totalEquityAndLiabilities = totalLiabilities + reportData.closingEquity;

            doc.fontSize(18).font('Helvetica-Bold').text('Balance Sheet', { align: 'center' });
            doc.fontSize(12).font('Helvetica').text(`As of ${formatDate(reportData.asOf)}`, { align: 'center' });
            doc.moveDown();

            doc.fontSize(14).font('Helvetica-Bold').text('ASSETS');
            doc.moveDown(0.5);
            doc.fontSize(12).font('Helvetica').text(`  Current Assets`).text(formatCurrency(reportData.assets.current), { align: 'right' });
            doc.text(`Total Current Assets`).text(formatCurrency(reportData.assets.current), { align: 'right' }).moveDown(0.5);

            doc.text(`  Non-current Assets`).text(formatCurrency(reportData.assets.non_current), { align: 'right' });
            doc.text(`Total Non-Current Assets`).text(formatCurrency(reportData.assets.non_current), { align: 'right' }).moveDown(0.5);

            doc.fontSize(14).font('Helvetica-Bold').text(`TOTAL ASSETS`).text(formatCurrency(totalAssets), { align: 'right' }).moveDown();

            doc.fontSize(14).font('Helvetica-Bold').text('EQUITY AND LIABILITIES');
            doc.moveDown(0.5);
            doc.fontSize(12).font('Helvetica').text(`  Current Liabilities`).text(formatCurrency(reportData.liabilities.current), { align: 'right' });
            doc.text(`Total Current Liabilities`).text(formatCurrency(reportData.liabilities.current), { align: 'right' }).moveDown(0.5);

            doc.text(`  Non-Current Liabilities`).text(formatCurrency(reportData.liabilities.non_current), { align: 'right' });
            doc.text(`Total Non-Current Liabilities`).text(formatCurrency(reportData.liabilities.non_current), { align: 'right' }).moveDown(0.5);

            doc.text(`TOTAL LIABILITIES`).text(formatCurrency(totalLiabilities), { align: 'right' }).moveDown(0.5);

            doc.fontSize(12).font('Helvetica').text(`  Equity`);
            doc.text(`    Opening Balance`).text(formatCurrency(reportData.openingEquity), { align: 'right' });
            doc.text(`    ${reportData.netProfitLoss >= 0 ? 'Net Profit for Period' : 'Net Loss for Period'}`).text(formatCurrency(Math.abs(reportData.netProfitLoss)), { align: 'right' });
            doc.text(`TOTAL EQUITY`).text(formatCurrency(reportData.closingEquity), { align: 'right' }).moveDown(0.5);

            doc.fontSize(14).font('Helvetica-Bold').text(`TOTAL EQUITY AND LIABILITIES`).text(formatCurrency(totalEquityAndLiabilities), { align: 'right' });
        }
        else if (documentType === 'cash-flow-statement') {
            doc.fontSize(18).font('Helvetica-Bold').text('Cash Flow Statement', { align: 'center' });
            doc.fontSize(12).font('Helvetica').text(`For the period ${formatDate(reportData.period.start)} to ${formatDate(reportData.period.end)}`, { align: 'center' });
            doc.moveDown();

            let netChange = 0;
            const categories = ['operating', 'investing', 'financing'];

            categories.forEach(cat => {
                const itemsRaw = reportData.sections[cat];
                if (Array.isArray(itemsRaw) && itemsRaw.length > 0) {
                    doc.fontSize(14).font('Helvetica-Bold').text(`${cat.charAt(0).toUpperCase() + cat.slice(1)} Activities`).moveDown(0.5);

                    let sectionTotal = 0;
                    itemsRaw.forEach((item: any) => {
                        const amount = parseFloat(item.amount.toString());
                        sectionTotal += amount;
                        doc.fontSize(12).font('Helvetica').text(`  ${item.line}`).text(formatCurrency(amount), { align: 'right' });
                    });

                    netChange += sectionTotal;
                    const subtotalLabel = sectionTotal >= 0
                        ? `Net cash from ${cat.charAt(0).toUpperCase() + cat.slice(1)} Activities`
                        : `Net cash used in ${cat.charAt(0).toUpperCase() + cat.slice(1)} Activities`;

                    doc.moveDown(0.5);
                    doc.fontSize(12).font('Helvetica-Bold').text(subtotalLabel).text(formatCurrency(sectionTotal), { align: 'right' }).moveDown();
                }
            });

            doc.fontSize(14).font('Helvetica-Bold').text('Net Increase / (Decrease) in Cash').text(formatCurrency(netChange), { align: 'right' });
        }
        else if (documentType === 'trial-balance') {
            doc.fontSize(18).font('Helvetica-Bold').text('Trial Balance', { align: 'center' });
            doc.fontSize(12).font('Helvetica').text(`As of ${formatDate(reportData.period.end)}`, { align: 'center' });
            doc.moveDown();

            // Table Headers
            const startX = 50;
            let x = startX;
            const y = doc.y;
            const colWidth = 150;
            doc.fontSize(12).font('Helvetica-Bold').text('Account', x, y);
            x += colWidth;
            doc.text('Debit', x, y, { width: colWidth, align: 'right' }); // Simplified label
            x += colWidth;
            doc.text('Credit', x, y, { width: colWidth, align: 'right' }); // Simplified label
            doc.moveDown();

            // Underline headers
            doc.moveTo(startX, doc.y).lineTo(startX + colWidth * 3, doc.y).stroke();

            // Table Rows
            reportData.items.forEach((item: any) => {
                x = startX;
                doc.fontSize(10).font('Helvetica');
                doc.text(`${item.code} - ${item.name}`, x, doc.y);
                x += colWidth;
                doc.text(formatCurrency(parseFloat(item.balance_debit)), x, doc.y, { width: colWidth, align: 'right' });
                x += colWidth;
                doc.text(formatCurrency(parseFloat(item.balance_credit)), x, doc.y, { width: colWidth, align: 'right' });
                doc.moveDown(0.3);
            });

            // Totals Row
            x = startX;
            doc.moveTo(startX, doc.y).lineTo(startX + colWidth * 3, doc.y).stroke(); // Line above totals
            doc.fontSize(12).font('Helvetica-Bold').text('TOTALS', x, doc.y);
            x += colWidth;
            doc.text(formatCurrency(reportData.totals.balance_debit), x, doc.y, { width: colWidth, align: 'right' });
            x += colWidth;
            doc.text(formatCurrency(reportData.totals.balance_credit), x, doc.y, { width: colWidth, align: 'right' });
        }

        // Optional: Add Footer
        const addFooter = () => {
            const bottom = doc.page.height - 50;
            doc.fontSize(10).font('Helvetica').text(`${companyName} | Generated on ${new Date().toLocaleDateString('en-ZA')}`, 50, bottom, { align: 'center', width: doc.page.width - 100 });
        };
        addFooter();

        doc.end();

    } catch (err: any) {
        console.error('Error in /generate-financial-document:', err);
        // Return a generic error response
        res.status(500).json({
            error: 'Failed to generate financial document',
            detail: err?.message || String(err)
        });
    }
});


// Profile endpoints
// GET /api/profile
app.get('/api/profile', authMiddleware, async (req: Request, res: Response) => {
  try {
    const userId = req.user?.user_id;
    if (!userId) return res.status(401).json({ error: 'User not authenticated.' });

    const result = await pool.query('SELECT * FROM public.users WHERE user_id = $1', [userId]);

    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).json({ error: 'Profile not found.' });
    }
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile.' });
  }
});



// Profile endpoints
// GET /api/profile






// Profile endpoints
// GET /api/profile
app.get('/api/profile', authMiddleware, async (req: Request, res: Response) => {
  try {
    const userId = req.user?.user_id;
    if (!userId) return res.status(401).json({ error: 'User not authenticated.' });

    const result = await pool.query('SELECT * FROM public.users WHERE user_id = $1', [userId]);

    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).json({ error: 'Profile not found.' });
    }
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile.' });
  }
});



/**
 * @route PUT /api/profile
 * @desc Update the current user's profile information
 * @access Private
 */
// PUT /api/profile
app.put('/api/profile', authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user?.user_id;
  if (!userId) return res.status(401).json({ error: 'User not authenticated.' });

  const {
    name,
    contact_person,
    email,
    phone,
    address,
    company,
    position,
    city,
    province,
    postal_code,
    country,
    bio,
    website,
    linkedin,
    timezone,
    currency,
    language,
  } = req.body;

  const query = `
    UPDATE public.users SET
      name = $1,
      contact_person = $2,
      email = $3,
      phone = $4,
      address = $5,
      company = $6,
      position = $7,
      city = $8,
      province = $9,
      postal_code = $10,
      country = $11,
      bio = $12,
      website = $13,
      linkedin = $14,
      timezone = $15,
      currency = $16,
      language = $17,
      updated_at = CURRENT_TIMESTAMP
    WHERE user_id = $18
    RETURNING *;
  `;

  const values = [
    name,
    contact_person,
    email,
    phone,
    address,
    company,
    position,
    city,
    province,
    postal_code,
    country,
    bio,
    website,
    linkedin,
    timezone,
    currency,
    language,
    userId,
  ];

  try {
    await pool.query('BEGIN');
    const result = await pool.query(query, values);
    await pool.query('COMMIT');

    if (result.rows.length > 0) {
      res.status(200).json({ message: 'Profile updated successfully.', updatedProfile: result.rows[0] });
    } else {
      res.status(404).json({ error: 'Profile not found.' });
    }
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update user profile.' });
  }
});

app.put('/api/profile/password', authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user?.user_id;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  const { password } = req.body;
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Invalid password' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('UPDATE public.users SET password_hash = $1 WHERE user_id = $2', [hashed, userId]);
    res.status(200).json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error('Password update error:', err);
    res.status(500).json({ error: 'Failed to update password.' });
  }
});


// Helper function to handle async queries and reduce boilerplate
async function queryDb<T>(queryText: string, params: any[]): Promise<T[]> {
  const client = await pool.connect();
  try {
    const res = await client.query(queryText, params);
    return res.rows;
  } finally {
    client.release();
  }
}
// Helper for the new endpoint to calculate baseline data
async function calculateBaselineData(userId: string) {
  // Define the start date as 12 months ago
  const twelveMonthsAgo = new Date();
  twelveMonthsAgo.setFullYear(twelveMonthsAgo.getFullYear() - 1);

  // Calculate Total Sales (Income)
  const salesQuery = `
    SELECT COALESCE(SUM(amount), 0) AS total_sales
    FROM public.transactions
    WHERE user_id = $1 AND type = 'income' AND date >= $2;
  `;
  const salesResult = await queryDb<{ total_sales: number }>(salesQuery, [userId, twelveMonthsAgo.toISOString()]);
  const totalSales = Number(salesResult[0]?.total_sales || 0);

  // Calculate Total Expenses
  const expensesQuery = `
    SELECT COALESCE(SUM(amount), 0) AS total_expenses
    FROM public.transactions
    WHERE user_id = $1 AND type = 'expense' AND date >= $2 AND category != 'Cost of Goods';
  `;
  const expensesResult = await queryDb<{ total_expenses: number }>(expensesQuery, [userId, twelveMonthsAgo.toISOString()]);
  const totalExpenses = Number(expensesResult[0]?.total_expenses || 0);
  
  // Calculate Total Costs (assuming a specific category for Cost of Goods)
  const cogsQuery = `
    SELECT COALESCE(SUM(amount), 0) AS total_cogs
    FROM public.transactions
    WHERE user_id = $1 AND type = 'expense' AND category = 'Cost of Goods' AND date >= $2;
  `;
  const cogsResult = await queryDb<{ total_cogs: number }>(cogsQuery, [userId, twelveMonthsAgo.toISOString()]);
  const totalCogs = Number(cogsResult[0]?.total_cogs || 0);

  // The final baseline data object
  return {
    sales: totalSales,
    costOfGoods: totalCogs,
    grossProfit: totalSales - totalCogs,
    totalExpenses: totalExpenses,
    netProfit: (totalSales - totalCogs) - totalExpenses,
  };
}

// --- START: UPDATED ENDPOINT FOR PROJECTIONS ---
// This endpoint now correctly calculates and returns baseline financial data.
app.get('/api/projections/baseline-data', authMiddleware, async (req: Request, res: Response) => {
  const companyId = req.user?.parent_user_id || req.user?.user_id;

  if (!companyId) {
    return res.status(401).json({ error: 'Unauthorized: Company ID (parent_user_id or user_id) not found.' });
  }

  try {
    // 1. Calculate total sales from all-time transactions (type 'income')
    const salesQuery = `
      SELECT COALESCE(SUM(amount), 0) as total_sales
      FROM public.transactions
      WHERE user_id = $1 AND type = 'income';
    `;
    const salesResult = await pool.query(salesQuery, [companyId]);
    const totalSales = parseFloat(salesResult.rows[0]?.total_sales) || 0;

    // 2. Calculate total cost of goods sold (COGS) from sale_items and products_services
    const cogsQuery = `
      SELECT COALESCE(SUM(si.quantity * ps.cost_price), 0) as total_cogs
      FROM public.sale_items si
      JOIN public.sales s ON si.sale_id = s.id
      JOIN public.products_services ps ON si.product_id = ps.id
      WHERE s.user_id = $1; -- Filter by the companyId associated with the sale
    `;
    const cogsResult = await pool.query(cogsQuery, [companyId]);
    const totalCogs = parseFloat(cogsResult.rows[0]?.total_cogs) || 0;

    // 3. Calculate total expenses from all-time transactions (type 'expense', excluding COGS)
    // Note: If you want to refine expenses further, ensure 'Cost of Goods' transactions are not double-counted here.
    const expensesQuery = `
      SELECT COALESCE(SUM(amount), 0) as total_expenses
      FROM public.transactions
      WHERE user_id = $1 AND type = 'expense' AND category != 'Cost of Goods';
    `;
    const expensesResult = await pool.query(expensesQuery, [companyId]);
    const totalExpenses = parseFloat(expensesResult.rows[0]?.total_expenses) || 0;

    // Construct the response object with the calculated values
    const baselineData = {
      sales: totalSales,
      costOfGoods: totalCogs,
      totalExpenses: totalExpenses,
    };

    res.status(200).json(baselineData);

  } catch (error) {
    console.error('Error fetching baseline data:', error);
    res.status(500).json({ error: 'Failed to fetch financial baseline data.' });
  }
});


// --- API Endpoints for User Management ---
// NOTE: These endpoints have been updated to remove the 'position' column
// and would require separate endpoints to manage user roles.
// GET /api/users  -> list users for this owner/company
// === helpers/auth.ts ===


// Helper function to manage agent records in the agents table
// Ensures an agent record exists/doesn't exist based on roles
export const syncAgentRecord = async (client: PoolClient, userId: string, userRoles: string[], parentUserId: string) => {
  const isAgent = userRoles.some(role => role.toLowerCase() === 'agent');

  if (isAgent) {
    // User has 'agent' role, ensure they exist in the agents table
    try {
      // Use INSERT ... ON CONFLICT to handle cases where the record might already exist
      // This assumes user_id is the PRIMARY KEY of the agents table
      await client.query(
        `INSERT INTO public.agents (user_id, parent_user_id)
         VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE
         SET parent_user_id = EXCLUDED.parent_user_id;`,
        [userId, parentUserId]
      );
      console.log(`[syncAgentRecord] Ensured agent record exists for user_id: ${userId}`);
    } catch (err) {
      console.error(`[syncAgentRecord] Error inserting/updating agent record for user_id ${userId}:`, err);
      throw err; // Re-throw to trigger rollback in calling function
    }
  } else {
    // User does not have 'agent' role, remove them from the agents table if they exist
    try {
      const deleteResult = await client.query(
        'DELETE FROM public.agents WHERE user_id = $1;',
        [userId]
      );
      if (deleteResult.rowCount && deleteResult.rowCount > 0) {
        console.log(`[syncAgentRecord] Removed agent record for user_id: ${userId}`);
      } else {
        console.log(`[syncAgentRecord] No agent record found to remove for user_id: ${userId}`);
      }
    } catch (err) {
      console.error(`[syncAgentRecord] Error deleting agent record for user_id ${userId}:`, err);
      throw err; // Re-throw to trigger rollback in calling function
    }
  }
};

export const getOwnerId = (req: Request) =>
  (req.user as any)?.parent_user_id || (req.user as any)?.user_id;

app.get('/api/users', authMiddleware, async (req: Request, res: Response) => {
  try {
    const ownerId = getOwnerId(req);
    const { rows } = await pool.query(
      `SELECT id, name, email
           FROM public.users
         WHERE parent_user_id = $1 OR user_id = $1
         ORDER BY name`,
      [ownerId]
    );
    res.json(rows);
  } catch (e:any) {
    console.error('users list error', e);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// 1. GET /users - Fetch all users belonging to the authenticated user's organization with their roles
app.get('/users', authMiddleware, async (req: Request, res: Response) => {
  const userId = (req as any).user?.user_id;

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized: User ID not found.' });
  }

  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.name AS "displayName",
        u.email,
        u.user_id,
        -- FIX START: Use json_agg(DISTINCT r.name) to prevent duplicate roles
        COALESCE(json_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '[]') AS roles
        -- FIX END
      FROM public.users u
      LEFT JOIN public.user_roles ur ON u.user_id = ur.user_id
      LEFT JOIN public.roles r ON ur.role = r.name
      WHERE u.parent_user_id = $1
      GROUP BY u.id, u.name, u.email, u.user_id
      ORDER BY u.name; -- Added ORDER BY for consistent results
    `, [userId]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to load users.' });
  }
});

// 2. POST /users - Create a new user within the authenticated user's organization
// 2. POST /users - Create a new user within the authenticated user's organization
app.post('/users', authMiddleware, async (req: Request, res: Response) => {
  const { displayName, email, role, password, officeCode } = req.body;
  const newUserId = uuidv4();
  const parentUserId = (req as any).user?.user_id; // This is the creator's user_id, who becomes the parent

  if (!displayName || !email || !password || !parentUserId) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  const userRole = (typeof role === 'string' && role.length > 0) ? role : 'user';
  
  const client = await pool.connect(); // Use a client for transaction

  try {
    const password_hash = await bcrypt.hash(password, 10);

    await client.query('BEGIN');

    // Correctly include the office_code in the INSERT statement
    const userInsertResult = await client.query(
      'INSERT INTO public.users (id, name, email, user_id, password_hash, parent_user_id, role, office_code) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, name AS "displayName", email, user_id, office_code',
      [uuidv4(), displayName, email, newUserId, password_hash, parentUserId, userRole, officeCode]
    );

    const roleInsertResult = await client.query('SELECT name FROM public.roles WHERE name = $1', [userRole]);
    if (roleInsertResult.rows.length === 0) {
      console.warn(`Role '${userRole}' does not exist and will not be assigned.`);
    } else {
        await client.query(
          'INSERT INTO public.user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [newUserId, userRole]
        );
    }

    // --- NEW: Sync agent record based on initial role ---
    // Pass the initial role as an array to the helper
    await syncAgentRecord(client, newUserId, [userRole], parentUserId);
    // --- END NEW ---

    await client.query('COMMIT');

    res.status(201).json(userInsertResult.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error adding new user:', err);
    
    if (err instanceof Error) {
        res.status(500).json({ error: err.message || 'Registration failed.' });
    } else {
      res.status(500).json({ error: 'Registration failed.' });
    }
  } finally {
    client.release(); // Release the client back to the pool
  }
});

// 3. PUT /users/:id - Update a user's basic details within the authenticated user's organization
// 4. PUT /users/:id/roles - Update a user's roles within the authenticated user's organization
// (Assuming this endpoint exists and looks something like this)
app.put('/users/:id/roles', authMiddleware, async (req: Request, res: Response) => {
  const { id: targetUserId } = req.params; // ID of the user whose roles are being changed
  const { roles: newRoles } = req.body; // Array of new roles
  const parentUserId = (req as any).user?.user_id; // ID of the user making the request (the parent/super-agent)

  if (!parentUserId) {
    return res.status(401).json({ error: 'Unauthorized: User ID not found.' });
  }

  if (!Array.isArray(newRoles)) {
    return res.status(400).json({ error: 'Roles must be an array of strings.' });
  }

  const client = await pool.connect();

  try {
    console.log(`[PUT /users/:id/roles] Attempting to update roles for user with id: ${targetUserId} under parent user: ${parentUserId}`);

    await client.query('BEGIN');

    // --- 1. Verify User Ownership ---
    // Check if the target user belongs to the parent user's organization
    const ownershipCheck = await client.query(
      'SELECT user_id, parent_user_id FROM public.users WHERE id = $1 AND parent_user_id = $2',
      [targetUserId, parentUserId]
    );

    if (ownershipCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      console.error(`[PUT /users/:id/roles] User ${targetUserId} not found or not under parent ${parentUserId}.`);
      return res.status(404).json({ error: 'User not found or not in your organization' });
    }
    const targetUserActualId = ownershipCheck.rows[0].user_id; // Get the actual user_id string
    const targetUserParentId = ownershipCheck.rows[0].parent_user_id; // Should match parentUserId

    // --- 2. Delete Existing Roles ---
    await client.query('DELETE FROM public.user_roles WHERE user_id = $1', [targetUserActualId]);

    // --- 3. Insert New Roles ---
    // Filter out empty or non-string roles for safety
    const validRoles = newRoles.filter(role => typeof role === 'string' && role.trim() !== '');
    if (validRoles.length > 0) {
        // Check if roles exist in the roles table (optional but good practice)
        const placeholders = validRoles.map((_, i) => `$${i + 1}`).join(', ');
        const checkRolesQuery = `SELECT name FROM public.roles WHERE name IN (${placeholders})`;
        const checkRolesResult = await client.query(checkRolesQuery, validRoles);

        const existingRoles = checkRolesResult.rows.map(row => row.name);
        const nonExistentRoles = validRoles.filter(role => !existingRoles.includes(role));
        if (nonExistentRoles.length > 0) {
            console.warn(`[PUT /users/:id/roles] The following roles do not exist and will not be assigned: ${nonExistentRoles.join(', ')}`);
        }

        // Insert only the roles that exist
        if (existingRoles.length > 0) {
            const insertPlaceholders = existingRoles.map((_, i) => `($1, $${i + 2})`).join(', ');
            const insertValues = [targetUserActualId, ...existingRoles];
            const insertQuery = `INSERT INTO public.user_roles (user_id, role) VALUES ${insertPlaceholders}`;
            await client.query(insertQuery, insertValues);
        }
    }

    // --- 4. NEW: Sync agent record based on updated roles ---
    await syncAgentRecord(client, targetUserActualId, validRoles, targetUserParentId);
    // --- END NEW ---

    await client.query('COMMIT');

    console.log(`[PUT /users/:id/roles] Roles successfully updated for user ${targetUserId}.`);
    res.status(200).json({ message: 'User roles updated successfully.' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[PUT /users/:id/roles] Error updating user roles:', err);
    res.status(500).json({ error: 'Failed to update user roles.', detail: err instanceof Error ? err.message : String(err) });
  } finally {
    client.release();
  }
});
// 4. DELETE /users/:id - Delete a user within the authenticated user's organization
app.delete('/users/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const parentUserId = (req as any).user?.user_id;

  if (!parentUserId) {
    return res.status(401).json({ error: 'Unauthorized: User ID not found.' });
  }

  try {
    console.log(`[DELETE /users/:id] Attempting to delete user with id: ${id} under parent user: ${parentUserId}`);
    
    // Use a transaction to ensure all related records are deleted or none are.
    const client = await pool.connect();
    await client.query('BEGIN');
    
    try {
      // First, find the user_id using the public-facing 'id' and 'parent_user_id'
      // Use '::uuid' to explicitly cast the input strings to UUID type.
      const userLookupResult = await client.query('SELECT user_id FROM public.users WHERE id = $1::uuid AND parent_user_id = $2::uuid', [id, parentUserId]);
      
      if (userLookupResult.rows.length === 0) {
        await client.query('ROLLBACK');
        console.error(`[DELETE /users/:id] User with id: ${id} and parent_user_id: ${parentUserId} not found.`);
        return res.status(404).json({ error: 'User not found or not in your organization' });
      }
      const targetUserUUID = userLookupResult.rows[0].user_id;

      // Delete from user_roles first due to foreign key constraints.
      await client.query('DELETE FROM public.user_roles WHERE user_id = $1::uuid', [targetUserUUID]);
      
      // Next, delete the agent record if one exists.
      await client.query('DELETE FROM public.agents WHERE user_id = $1::uuid', [targetUserUUID]);

      // Finally, delete the user record itself.
      // Use '::uuid' for casting here as well.
      const result = await client.query('DELETE FROM public.users WHERE id = $1::uuid AND parent_user_id = $2::uuid RETURNING id', [id, parentUserId]);
      
      if (result.rows.length === 0) {
        // This should ideally not be reached if the user was found in the first step
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found or not in your organization' });
      }

      await client.query('COMMIT');
      res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err; // Re-throw to be caught by the outer catch block
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Deletion failed.' });
  }
});


// New endpoint to update user roles
app.put('/users/:id/roles', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { roles } = req.body;
  const parentUserId = (req as any).user?.user_id;

  if (!parentUserId) {
    return res.status(401).json({ error: 'Unauthorized: User ID not found.' });
  }

  if (!Array.isArray(roles)) {
    return res.status(400).json({ error: 'Roles must be an array of strings.' });
  }

  try {
    console.log(`[PUT /users/:id/roles] Attempting to update roles for user with id: ${id} under parent user: ${parentUserId}`);
    await pool.query('BEGIN');
    
    // Check for user existence and get the user_id before proceeding to delete/insert roles
    const userResult = await pool.query('SELECT user_id FROM public.users WHERE id = $1 AND parent_user_id = $2', [id, parentUserId]);
    if (userResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found or not in your organization' });
    }
    const targetUserId = userResult.rows[0].user_id;

    // First, remove all existing roles for this user
    await pool.query('DELETE FROM public.user_roles WHERE user_id = $1', [targetUserId]);
    
    // Then, insert the new roles
    const roleInsertPromises = roles.map(async (roleName) => {
      // Check if the role exists before inserting
      const roleResult = await pool.query('SELECT name FROM public.roles WHERE name = $1', [roleName]);
      if (roleResult.rows.length > 0) {
        // Insert the user-role mapping.
        await pool.query(
          'INSERT INTO public.user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [targetUserId, roleName]
        );
      } else {
        console.warn(`Role '${roleName}' does not exist and will not be assigned.`);
      }
    });

    await Promise.all(roleInsertPromises);
    await pool.query('COMMIT');

    res.status(200).json({ message: 'User roles updated successfully' });
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('Error updating user roles:', err);
    if (err instanceof Error) {
      res.status(500).json({ error: err.message || 'Failed to update roles.' });
    } else {
      res.status(500).json({ error: 'Failed to update roles.' });
    }
  }
});

// Assuming 'app', 'authMiddleware', 'pool', 'Request', 'Response' are defined elsewhere

// NEW: Top Selling Products (using sale_items and sales tables)
app.get('/api/charts/top-selling-products', authMiddleware, async (req, res) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(`
      SELECT
        si.product_name,
        SUM(si.quantity) AS total_quantity_sold
      FROM sale_items si
      JOIN sales s ON si.sale_id = s.id
      WHERE s.user_id = $1
      GROUP BY si.product_name
      ORDER BY total_quantity_sold DESC
      LIMIT 5;
    `, [user_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching top-selling products:', error);
    res.status(500).json({ error: 'Failed to fetch top-selling products' });
  }
});

// Existing Endpoints (unchanged, but included for context)
// Customer Lifetime Value: NOW dynamically calculates total_invoiced from sales table
app.get('/api/charts/customer-lifetime-value', authMiddleware, async (req, res) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(`
      SELECT
        CASE
          WHEN COALESCE(customer_sales.total_customer_sales, 0) < 1000 THEN 'Low Value (<R1000)'
          WHEN COALESCE(customer_sales.total_customer_sales, 0) BETWEEN 1000 AND 5000 THEN 'Medium Value (R1000-R5000)'
          ELSE 'High Value (>R5000)'
        END AS bucket,
        COUNT(c.id) AS count
      FROM customers c
      LEFT JOIN (
          SELECT
              s.customer_id,
              SUM(s.total_amount) AS total_customer_sales
          FROM sales s
          WHERE s.user_id = $1
          GROUP BY s.customer_id
      ) AS customer_sales ON c.id = customer_sales.customer_id
      WHERE c.user_id = $1
      GROUP BY bucket;
    `, [user_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching customer value distribution:', error);
    res.status(500).json({ error: 'Failed to fetch customer value chart' });
  }
});


app.get('/api/charts/product-stock-levels', authMiddleware, async (req, res) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(`
      SELECT name, stock_quantity, min_quantity, max_quantity
      FROM products_services
      WHERE user_id = $1
    `, [user_id]);

    const transformed = result.rows.map(row => ({
      name: row.name,
      current: row.stock_quantity,
      min: row.min_quantity,
      max: row.max_quantity,
    }));

    res.json(transformed);
  } catch (error) {
    console.error('Error fetching stock levels:', error);
    res.status(500).json({ error: 'Failed to fetch stock level chart' });
  }
});


app.get('/api/charts/transaction-type-breakdown', authMiddleware, async (req, res) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(`
      SELECT 
        TO_CHAR(date, 'YYYY-MM') AS month,
        type,
        SUM(amount) AS total
      FROM transactions
      WHERE user_id = $1
      GROUP BY month, type
      ORDER BY month
    `, [user_id]);

    // 🔧 Explicitly type the shape of the aggregated data
    interface MonthlyBreakdown {
      sale: number;
      income: number;
      expense: number;
      cash_in: number;
    }

    const data: Record<string, MonthlyBreakdown> = {};

    for (const row of result.rows) {
      const month = row.month as string;
      const type = row.type as keyof MonthlyBreakdown;
      const total = Number(row.total);

      if (!data[month]) {
        data[month] = { sale: 0, income: 0, expense: 0, cash_in: 0 };
      }

      // 🧠 Type-safe assignment
      if (type in data[month]) {
        data[month][type] += total;
      }
    }

    res.json(data);
  } catch (error) {
    console.error('Error fetching transaction breakdown:', error);
    res.status(500).json({ error: 'Failed to fetch breakdown' });
  }
});



app.get('/api/charts/payroll-distribution', authMiddleware, async (req, res) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(`
      SELECT 
        TO_CHAR(created_at, 'YYYY-MM') AS month,
        SUM(
          CASE 
            WHEN payment_type = 'salary' THEN base_salary
            ELSE hourly_rate * hours_worked_total
          END
        ) AS total_payroll
      FROM employees
      WHERE user_id = $1
      GROUP BY month
      ORDER BY month
    `, [user_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching payroll distribution:', error);
    res.status(500).json({ error: 'Failed to fetch payroll chart' });
  }
});

// helpers/scope.ts
export const getTenantId = (req: any) =>
  req.user?.parent_user_id ?? req.user?.user_id;

// GET /api/tellers
// GET /api/tellers?date=YYYY-MM-DD
app.get('/api/tellers', authMiddleware, async (req, res) => {
  try {
    const tenantId = req.user?.parent_user_id ?? req.user?.user_id;
    const qDate = typeof req.query.date === 'string' ? req.query.date : undefined;
    const date =
      qDate && /^\d{4}-\d{2}-\d{2}$/.test(qDate) ? qDate : new Date().toISOString().slice(0, 10);

    const { rows } = await pool.query(
      `
      SELECT
        u.user_id AS id,
        u.name,
        u.email,
        u.phone,
        u.position,
        COALESCE(u.company, u.address, '') AS branch
      FROM public.users u
      JOIN (
        SELECT DISTINCT teller_id
        FROM public.sales
        WHERE user_id = $1
          AND teller_id IS NOT NULL
          AND ((created_at AT TIME ZONE 'Africa/Johannesburg')::date) = $2::date
      ) s ON s.teller_id = u.user_id
      WHERE u.parent_user_id = $1
      ORDER BY u.name ASC
      `,
      [tenantId, date]
    );

    res.json(rows.map(r => ({ ...r, userRole: 'teller' }))); // shape the FE expects
  } catch (e) {
    console.error('GET /api/tellers error', e);
    res.status(500).json({ error: 'Failed to load tellers' });
  }
});


// GET /api/reconciliation/expected?date=YYYY-MM-DD
app.get('/api/reconciliation/expected', authMiddleware, async (req, res) => {
  try {
    const tenantId = getTenantId(req);
    const qDate = typeof req.query.date === 'string' ? req.query.date : undefined;
    const date =
      qDate && /^\d{4}-\d{2}-\d{2}$/.test(qDate) ? qDate : new Date().toISOString().slice(0, 10);

    const { rows } = await pool.query(
      `
      SELECT
        s.teller_id,
        COALESCE(SUM(
          CASE
            WHEN s.payment_type = 'Cash'
            THEN COALESCE(s.amount_paid, 0) - COALESCE(s.change_given, 0)
            ELSE 0
          END
        ), 0) AS cash,
        COALESCE(SUM(
          CASE
            WHEN s.payment_type = 'Bank'
            THEN COALESCE(s.amount_paid, 0)
            ELSE 0
          END
        ), 0) AS bank,
        COALESCE(SUM(
          CASE
            WHEN s.payment_type = 'Credit'
            THEN COALESCE(s.credit_amount, 0)
            ELSE 0
          END
        ), 0) AS credit
      FROM public.sales s
      WHERE s.user_id = $1
        AND ((s.created_at AT TIME ZONE 'Africa/Johannesburg')::date) = $2::date
      GROUP BY s.teller_id
      `,
      [tenantId, date]
    );

    const map: Record<string, { cash: number; bank: number; credit: number }> = {};
    for (const r of rows) {
      map[String(r.teller_id)] = {
        cash: Number(r.cash || 0),
        bank: Number(r.bank || 0),
        credit: Number(r.credit || 0),
      };
    }
    res.json(map);
  } catch (e) {
    console.error('GET /api/reconciliation/expected error', e);
    res.status(500).json({ error: 'Failed to compute expected totals' });
  }
});

// POST /api/reconciliation/submit
app.post('/api/reconciliation/submit', authMiddleware, async (req, res) => {
  try {
    const tenantId = getTenantId(req);
    const recordedBy = req.user!.user_id;

    const { tellerId, expectedCash, countedCash, variance, notes, date } = req.body;
    if (tellerId == null || expectedCash == null || countedCash == null || variance == null) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const reconDate =
      typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date)
        ? date
        : new Date().toISOString().slice(0, 10);

    const { rows } = await pool.query(
      `
      INSERT INTO cash_reconciliations
        (user_id, teller_user_id, expected_cash, counted_cash, variance, notes, recorded_by, recon_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT ON CONSTRAINT uq_cash_recon_user_teller_day DO NOTHING
      RETURNING id, user_id, teller_user_id, expected_cash, counted_cash, variance, notes, recorded_by, recon_date, created_at
      `,
      [tenantId, tellerId, expectedCash, countedCash, variance, notes || null, recordedBy, reconDate]
    );

    if (!rows.length) {
      return res.status(409).json({ error: 'Reconciliation already recorded for this teller and date' });
    }

    res.json(rows[0]);
  } catch (e) {
    console.error('POST /api/reconciliation/submit error', e);
    res.status(500).json({ error: 'Failed to submit reconciliation' });
  }
});



// ===== Teller record APIs =====
app.get('/api/reconciliation/history', authMiddleware, async (req, res) => {
  try {
    const tenantId = getTenantId(req);
    const tellerId = String(req.query.tellerId || '');
    const from = String(req.query.from || '');
    const to   = String(req.query.to || '');
    if (!tellerId || !from || !to) {
      return res.status(400).json({ error: 'tellerId, from, to are required' });
    }

    const { rows } = await pool.query(
      `
      SELECT
        recon_date AS day,
        expected_cash,
        counted_cash,
        variance,
        notes,
        recorded_by,
        created_at
      FROM public.cash_reconciliations
      WHERE user_id = $1
        AND teller_user_id = $2
        AND recon_date BETWEEN $3::date AND $4::date
      ORDER BY recon_date DESC
      `,
      [tenantId, tellerId, from, to]
    );

    res.json({ rows });
  } catch (e) {
    console.error('GET /api/reconciliation/history error', e);
    res.status(500).json({ error: 'Failed to load history' });
  }
});

app.get('/api/reconciliation/missed-days', authMiddleware, async (req, res) => {
  try {
    const tenantId = getTenantId(req);
    const tellerId = String(req.query.tellerId || '');
    const from = String(req.query.from || '');
    const to   = String(req.query.to || '');
    if (!tellerId || !from || !to) {
      return res.status(400).json({ error: 'tellerId, from, to are required' });
    }

    // Days with cash sales but NO reconciliation
    const { rows } = await pool.query(
      `
      WITH days AS (
        SELECT d::date AS day
        FROM generate_series($3::date, $4::date, interval '1 day') AS d
      ),
      daily_sales AS (
        SELECT
          (s.created_at AT TIME ZONE 'Africa/Johannesburg')::date AS day,
          SUM(CASE WHEN s.payment_type = 'Cash'
                   THEN COALESCE(s.amount_paid,0) - COALESCE(s.change_given,0)
                   ELSE 0 END) AS cash,
          SUM(CASE WHEN s.payment_type = 'Bank' THEN COALESCE(s.amount_paid,0) ELSE 0 END) AS bank,
          SUM(CASE WHEN s.payment_type = 'Credit' THEN COALESCE(s.credit_amount,0) ELSE 0 END) AS credit
        FROM public.sales s
        WHERE s.user_id = $1
          AND s.teller_id = $2
          AND (s.created_at AT TIME ZONE 'Africa/Johannesburg')::date BETWEEN $3::date AND $4::date
        GROUP BY 1
      )
      SELECT
        d.day,
        COALESCE(ds.cash, 0)   AS cash,
        COALESCE(ds.bank, 0)   AS bank,
        COALESCE(ds.credit, 0) AS credit
      FROM days d
      LEFT JOIN daily_sales ds ON ds.day = d.day
      WHERE COALESCE(ds.cash,0) > 0  -- had cash sales
        AND NOT EXISTS (
          SELECT 1 FROM public.cash_reconciliations cr
          WHERE cr.user_id = $1
            AND cr.teller_user_id = $2
            AND cr.recon_date = d.day
        )
      ORDER BY d.day DESC
      `,
      [tenantId, tellerId, from, to]
    );

    res.json({ rows });
  } catch (e) {
    console.error('GET /api/reconciliation/missed-days error', e);
    res.status(500).json({ error: 'Failed to load missed days' });
  }
});

app.get('/api/reconciliation/short-days', authMiddleware, async (req, res) => {
  try {
    const tenantId = getTenantId(req);
    const tellerId = String(req.query.tellerId || '');
    const from = String(req.query.from || '');
    const to   = String(req.query.to || '');
    if (!tellerId || !from || !to) {
      return res.status(400).json({ error: 'tellerId, from, to are required' });
    }

    // Rows where variance < 0 (short)
    const rowsQ = pool.query(
      `
      SELECT
        recon_date AS day,
        expected_cash,
        counted_cash,
        variance,
        notes
      FROM public.cash_reconciliations
      WHERE user_id = $1
        AND teller_user_id = $2
        AND recon_date BETWEEN $3::date AND $4::date
        AND variance < 0
      ORDER BY recon_date DESC
      `,
      [tenantId, tellerId, from, to]
    );

    // Totals for the tab header (return shortage as positive)
    const totalsQ = pool.query(
      `
      SELECT
        COUNT(*)::int                                       AS days,
        COALESCE(SUM(expected_cash), 0)::numeric(12,2)      AS total_expected,
        COALESCE(SUM(counted_cash), 0)::numeric(12,2)       AS total_counted,
        COALESCE(SUM(-variance), 0)::numeric(12,2)          AS total_shortage
      FROM public.cash_reconciliations
      WHERE user_id = $1
        AND teller_user_id = $2
        AND recon_date BETWEEN $3::date AND $4::date
        AND variance < 0
      `,
      [tenantId, tellerId, from, to]
    );

    const [rowsRes, totalsRes] = await Promise.all([rowsQ, totalsQ]);
    res.json({ rows: rowsRes.rows, totals: totalsRes.rows[0] });
  } catch (e) {
    console.error('GET /api/reconciliation/short-days error', e);
    res.status(500).json({ error: 'Failed to load short days' });
  }
});

// NEW ENDPOINT: GET Sales, Expenses, and Other Categories for Sunburst Chart
app.get('/api/charts/sales-expenses-sunburst', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    const { startDate, endDate } = req.query;

    try {
        // Shared date filter parameters, applied to the 'date' column in transactions
        let dateFilter = '';
        const sharedQueryParams: (string | number)[] = [user_id];
        let paramIndex = 2; // Start index for additional parameters

        if (startDate) {
            dateFilter += ` AND date >= $${paramIndex++}`; // Use 'date' column for filtering
            sharedQueryParams.push(startDate as string);
        }
        if (endDate) {
            dateFilter += ` AND date <= $${paramIndex++}`; // Use 'date' column for filtering
            sharedQueryParams.push(endDate as string);
        }

        // Fetch Revenue from public.transactions, categorized
        const revenueCategoriesResult = await pool.query(`
            SELECT
                category,
                COALESCE(SUM(amount), 0) AS value
            FROM public.transactions
            WHERE
                user_id = $1
                AND type = 'income' -- Assuming 'income' type for revenue
                AND category IN ('Revenue', 'Sales Revenue') -- Specific categories for sales/revenue
                ${dateFilter}
            GROUP BY category;
        `, sharedQueryParams);

        // Fetch Expenses from public.transactions, categorized
        const expenseCategoriesResult = await pool.query(`
            SELECT
                category,
                COALESCE(SUM(amount), 0) AS value
            FROM public.transactions
            WHERE
                user_id = $1
                AND type = 'expense' -- Assuming 'expense' type for expenses
                ${dateFilter}
            GROUP BY category;
        `, sharedQueryParams);

        // Fetch Other Income from public.transactions, categorized
        // This will capture any income not explicitly tagged as 'Revenue' or 'Sales Revenue'
        const otherIncomeCategoriesResult = await pool.query(`
            SELECT
                category,
                COALESCE(SUM(amount), 0) AS value
            FROM public.transactions
            WHERE
                user_id = $1
                AND type = 'income'
                AND category NOT IN ('Revenue', 'Sales Revenue')
                ${dateFilter}
            GROUP BY category;
        `, sharedQueryParams);

        let totalSales = 0;
        let totalExpenses = 0;
        let totalOtherIncome = 0;

        const sunburstData: { id: string; parent?: string; name: string; value?: number; color?: string; }[] = [];

        // Add top-level nodes for 'Revenue', 'Expenses', 'Other Income'
        sunburstData.push({ id: 'revenue-parent', parent: 'total', name: 'Revenue', color: '#4CAF50' }); // Green for Revenue
        sunburstData.push({ id: 'expenses-parent', parent: 'total', name: 'Expenses', color: '#F44336' }); // Red for Expenses
        sunburstData.push({ id: 'other-income-parent', parent: 'total', name: 'Other Income', color: '#FFC107' }); // Amber for Other Income

        // Process Revenue Categories
        revenueCategoriesResult.rows.forEach(row => {
            const value = parseFloat(row.value);
            if (value > 0) { // Only include categories with actual value
                totalSales += value;
                sunburstData.push({
                    id: `revenue-${row.category.toLowerCase().replace(/\s/g, '-')}`,
                    parent: 'revenue-parent',
                    name: row.category,
                    value: value
                });
            }
        });

        // Process Expense Categories
        expenseCategoriesResult.rows.forEach(row => {
            const value = parseFloat(row.value);
            if (value > 0) { // Only include categories with actual value
                totalExpenses += value;
                sunburstData.push({
                    id: `expense-${row.category.toLowerCase().replace(/\s/g, '-')}`,
                    parent: 'expenses-parent',
                    name: row.category,
                    value: value
                });
            }
        });

        // Process Other Income Categories
        otherIncomeCategoriesResult.rows.forEach(row => {
            const value = parseFloat(row.value);
            if (value > 0) { // Only include categories with actual value
                totalOtherIncome += value;
                sunburstData.push({
                    id: `other-income-${row.category.toLowerCase().replace(/\s/g, '-')}`,
                    parent: 'other-income-parent',
                    name: row.category,
                    value: value
                });
            }
        });

        // Add the overall 'total' node after calculating sums
        const overallTotal = totalSales + totalExpenses + totalOtherIncome;
        sunburstData.unshift({ id: 'total', name: 'Financial Overview', value: overallTotal });


        res.json(sunburstData);

    } catch (error: unknown) {
        console.error('Error fetching sunburst data:', error);
        res.status(500).json({ error: 'Failed to fetch sunburst data', detail: error instanceof Error ? error.message : String(error) });
    }
});

// Helper function to calculate previous period dates based on the current period
const getPreviousPeriodDates = (startDateStr: string, endDateStr: string) => {
    const startDate = new Date(startDateStr);
    const endDate = new Date(endDateStr);

    // Calculate the duration of the current period in milliseconds
    const periodDurationMs = endDate.getTime() - startDate.getTime();

    // The previous period's end date is the day before the current period's start date
    const prevEndDate = new Date(startDate);
    prevEndDate.setDate(startDate.getDate() - 1);

    // The previous period's start date is `periodDurationMs` before the prevEndDate
    const prevStartDate = new Date(prevEndDate.getTime() - periodDurationMs);

    return {
        prevStartDate: prevStartDate.toISOString().split('T')[0],
        prevEndDate: prevEndDate.toISOString().split('T')[0],
    };
};

// NEW ENDPOINT: GET Revenue Statistics for a period (or all time)


// NEW ENDPOINT: GET Expenses Statistics for a period (or all time)


// Existing /api/stats/clients endpoint, modified to allow all-time view and use public.sales
app.get('/api/stats/clients', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    // startDate and endDate can now be optional
    const { startDate, endDate } = req.query as { startDate?: string; endDate?: string };

    try {
        let currentPeriodCount = 0;
        let previousPeriodCount = 0;
        let changePercentage: number | undefined;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';

        let dateFilterClause = '';
        const currentQueryParams: (string | number)[] = [user_id];
        let currentParamIndex = 2;

        // If both startDate and endDate are provided, build the date filter clause for 'created_at'
        if (startDate && endDate) {
            dateFilterClause = ` AND created_at BETWEEN $${currentParamIndex++} AND $${currentParamIndex++}`;
            currentQueryParams.push(startDate);
            currentQueryParams.push(endDate);
        }

        // Fetch current period client count (or all-time if no dates provided)
        // Now counting distinct customer_id from public.sales table
        const currentClientsResult = await pool.query(`
            SELECT COUNT(DISTINCT customer_id) AS count
            FROM public.sales
            WHERE user_id = $1
            ${dateFilterClause};
        `, currentQueryParams);
        currentPeriodCount = parseInt(currentClientsResult.rows[0]?.count || 0, 10);

        // Only calculate previous period and change if a specific date range was provided
        if (startDate && endDate) {
            const { prevStartDate, prevEndDate } = getPreviousPeriodDates(startDate, endDate);
            const previousQueryParams: (string | number)[] = [user_id, prevStartDate, prevEndDate];

            // Fetch previous period client count
            // Now counting distinct customer_id from public.sales table
            const previousClientsResult = await pool.query(`
                SELECT COUNT(DISTINCT customer_id) AS count
                FROM public.sales
                WHERE user_id = $1
                AND created_at BETWEEN $2 AND $3;
            `, previousQueryParams);
            previousPeriodCount = parseInt(previousClientsResult.rows[0]?.count || 0, 10);

            // Calculate change percentage
            if (previousPeriodCount !== 0) {
                changePercentage = ((currentPeriodCount - previousPeriodCount) / previousPeriodCount) * 100;
                if (changePercentage > 0) {
                    changeType = 'increase';
                } else if (changePercentage < 0) {
                    changeType = 'decrease';
                }
            } else if (currentPeriodCount > 0) {
                changePercentage = 100; // Infinite increase from zero to a positive value
                changeType = 'increase';
            }
        }

        res.json({
            count: currentPeriodCount,
            previousCount: previousPeriodCount,
            changePercentage: changePercentage !== undefined ? parseFloat(changePercentage.toFixed(2)) : undefined,
            changeType: changeType
        });

    } catch (error: unknown) {
        console.error('Error fetching client stats:', error);
        res.status(500).json({ error: 'Failed to fetch client statistics', detail: error instanceof Error ? error.message : String(error) });
    }
});

const logoBucket = 'company-logos';
const uploadLogo = multer({ limits: { fileSize: 5 * 1024 * 1024 } });
// POST /upload-logo
app.post('/upload-logo', authMiddleware, uploadLogo.single('logo'), async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const user_id = req.user!.user_id;
  const uniqueFileName = `${user_id}/${Date.now()}_${req.file.originalname}`;

  try {
    const { data, error: uploadError } = await supabase.storage
      .from(logoBucket)
      .upload(uniqueFileName, req.file.buffer, {
        cacheControl: '3600',
        upsert: true,
        contentType: req.file.mimetype,
        duplex: 'half',
      });

    if (uploadError) {
      console.error('Supabase upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload logo.' });
    }

    // Persist on users row
    await pool.query(
      `UPDATE public.users
         SET company_logo_bucket = $1,
             company_logo_path   = $2,
             company_logo_mime   = $3,
             company_logo_updated_at = NOW()
       WHERE user_id = $4`,
      [logoBucket, data!.path, req.file.mimetype, user_id]
    );

    // Match your documents upload response shape
    res.status(201).json({
      message: 'Logo uploaded successfully!',
      filePath: data!.path,
    });
  } catch (error) {
    console.error('Unexpected error (logo upload):', error);
    // Best effort cleanup if we already uploaded
    if (uniqueFileName) {
      await supabase.storage.from(logoBucket).remove([uniqueFileName]);
    }
    res.status(500).json({ error: 'An unexpected error occurred while uploading the logo.' });
  }
});

// GET /logo  → returns { url } (signed for 1 hour)
app.get('/logo', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.user_id;

  try {
    const { rows } = await pool.query(
      `SELECT company_logo_path
         FROM public.users
        WHERE user_id = $1
        LIMIT 1`,
      [user_id]
    );

    const filePath = rows?.[0]?.company_logo_path || null;
    if (!filePath) {
      return res.status(200).json({ url: null });
    }

    const { data, error } = await supabase.storage
      .from(logoBucket)
      .createSignedUrl(filePath, 3600); // 1 hour

    if (error) {
      console.error('Error creating signed URL:', error);
      return res.status(500).json({ error: 'Failed to generate logo URL.' });
    }

    return res.status(200).json({ url: data.signedUrl });
  } catch (error) {
    console.error('Error fetching logo:', error);
    res.status(500).json({ error: 'Failed to fetch logo.' });
  }
});

// GET /logo/download  → redirect to signed URL (like /documents/:id/download)
app.get('/logo/download', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.user_id;

  try {
    const { rows } = await pool.query(
      `SELECT company_logo_path
         FROM public.users
        WHERE user_id = $1
        LIMIT 1`,
      [user_id]
    );

    if (!rows.length || !rows[0].company_logo_path) {
      return res.status(404).json({ error: 'Logo not found.' });
    }

    const filePath = rows[0].company_logo_path;

    const { data, error } = await supabase.storage
      .from(logoBucket)
      .createSignedUrl(filePath, 3600);

    if (error) {
      console.error('Error creating signed URL:', error);
      return res.status(500).json({ error: 'Failed to generate download link.' });
    }

    return res.redirect(data.signedUrl);
  } catch (error) {
    console.error('Error during logo download:', error);
    res.status(500).json({ error: 'Failed to process download request.' });
  }
});

// DELETE /logo  → delete from storage, then clear columns
app.delete('/logo', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.user_id;

  try {
    // 1) Fetch current path
    const { rows } = await pool.query(
      `SELECT company_logo_path
         FROM public.users
        WHERE user_id = $1
        LIMIT 1`,
      [user_id]
    );

    if (!rows.length || !rows[0].company_logo_path) {
      return res.status(204).send(); // nothing to delete
    }

    const filePath = rows[0].company_logo_path;

    // 2) Remove from storage first (so we only clear DB if storage succeeded)
    const { error: storageError } = await supabase.storage.from(logoBucket).remove([filePath]);
    if (storageError) {
      console.error('Supabase storage deletion error (logo):', storageError);
      return res.status(500).json({ error: 'Failed to delete logo from storage.' });
    }

    // 3) Clear DB columns
    await pool.query(
      `UPDATE public.users
          SET company_logo_path = NULL,
              company_logo_mime = NULL,
              company_logo_updated_at = NULL
        WHERE user_id = $1`,
      [user_id]
    );

    return res.status(204).send();
  } catch (error) {
    console.error('Error deleting logo:', error);
    res.status(500).json({ error: 'Failed to delete logo.' });
  }
});

app.get('/api/profile', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;

    try {
        const { rows } = await pool.query(
            `SELECT company, email, address, city, province, postal_code, country, phone,  company_logo_path
             FROM public.users
             WHERE user_id = $1`,
            [user_id]
        );

        if (!rows.length) {
            return res.status(404).json({ message: 'User profile not found.' });
        }

        const userProfile = rows[0];

        // NEW: Get the public URL for the company logo if a path exists
        let companyLogoUrl = null;
        if (userProfile.company_logo_path) {
            const { data } = supabase.storage.from('company_logos').getPublicUrl(userProfile.company_logo_path);
            companyLogoUrl = data.publicUrl;
        }

        // Return the user profile along with the logo URL
        res.status(200).json({ ...userProfile, company_logo_url: companyLogoUrl });

    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile.' });
    }
});

// In your main server file (e.g., server.ts or routes/customers.ts)
// server.ts

// server.ts

// POST /api/applications - Create a new customer application
// POST /api/applications - Create a new customer application
// POST /api/applications - Create a new customer application
// POST /api/applications - Create a new customer application
// POST /api/applications - Create a new customer application
app.post('/api/applications', authMiddleware, async (req: Request, res: Response) => {
    const {
        name, surname, phone, email, address, nationality, gender, date_of_birth, id_number, alt_name, relation_to_member, relation_dob,
        family_members, plan_options, extended_family,
        beneficiary_name, beneficiary_surname, beneficiary_contact, pay_options, total_amount, bank, branch_code, account_holder, account_number, deduction_date, account_type, commencement_date,
        declaration_signature, declaration_date, call_time, agent_name,
        connector_name, connector_contact, connector_province, team_leader, team_contact, team_province
    } = req.body;

    // The code correctly identifies the parent and agent user IDs
    const parentUserId = req.user!.parent_user_id;
    const agentUserId = req.user!.user_id;

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Insert into the main applications table
        const applicationQuery = `
            INSERT INTO public.applications (
                user_id, parent_user_id, name, surname, phone, email, address, nationality, gender, date_of_birth, id_number,
                alt_name, relation_to_member, relation_dob, plan_options, beneficiary_name, beneficiary_surname,
                beneficiary_contact, pay_options, total_amount, bank, branch_code, account_holder, account_number,
                deduction_date, account_type, commencement_date, declaration_signature, declaration_date,
                call_time, agent_name, connector_name, connector_contact, connector_province, team_leader,
                team_contact, team_province
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)
            RETURNING id;
        `;
        const applicationResult = await client.query(applicationQuery, [
            agentUserId, parentUserId, name, surname, phone, email, address, nationality, gender, date_of_birth, id_number,
            alt_name, relation_to_member, relation_dob, plan_options, beneficiary_name, beneficiary_surname,
            beneficiary_contact, pay_options, total_amount, bank, branch_code, account_holder, account_number,
            deduction_date, account_type, commencement_date, declaration_signature, declaration_date,
            call_time, agent_name, connector_name, connector_contact, connector_province, team_leader,
            team_contact, team_province
        ]);
        const newApplicationId = applicationResult.rows[0].id;

        // Insert family members
        if (Array.isArray(family_members) && family_members.length > 0) {
            const familyQuery = `INSERT INTO public.family_members (application_id, name, surname, relationship, date_of_birth) VALUES ($1, $2, $3, $4, $5);`;
            for (const member of family_members) {
                // Basic validation could be added here if needed
                await client.query(familyQuery, [newApplicationId, member.name, member.surname, member.relationship, member.date_of_birth]);
            }
        }

        // Insert extended family members
        if (Array.isArray(extended_family) && extended_family.length > 0) {
            const extendedFamilyQuery = `INSERT INTO public.extended_family (application_id, name, surname, relationship, date_of_birth, premium) VALUES ($1, $2, $3, $4, $5, $6);`;
            for (const member of extended_family) {
                   // Basic validation could be added here if needed
                await client.query(extendedFamilyQuery, [newApplicationId, member.name, member.surname, member.relationship, member.date_of_birth, member.premium]);
            }
        }

        await client.query('COMMIT');
        res.status(201).json({ message: 'Application created successfully!', id: newApplicationId });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error creating application:', error);
        res.status(500).json({ error: 'Failed to create application.', details: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// GET /api/applications - Get all applications for the authenticated user's scope
app.get('/api/applications', authMiddleware, async (req: Request, res: Response) => {
    // This now fetches applications associated with the direct agent's user_id
    const user_id = req.user!.user_id;
    const client = await pool.connect();

    try {
        // Fetch applications created by the logged-in agent
        const applicationsQuery = `
            SELECT
                a.id, a.name, a.surname, a.phone, a.email, a.address, a.nationality, a.gender,
                a.date_of_birth, a.id_number, a.alt_name, a.relation_to_member, a.relation_dob,
                a.plan_options, a.beneficiary_name, a.beneficiary_surname, a.beneficiary_contact,
                a.pay_options, a.total_amount, a.bank, a.branch_code, a.account_holder,
                a.account_number, a.deduction_date, a.account_type, a.commencement_date,
                a.declaration_signature, a.declaration_date, a.call_time, a.agent_name,
                a.connector_name, a.connector_contact, a.connector_province, a.team_leader,
                a.team_contact, a.team_province,
                a.created_at, a.updated_at
            FROM public.applications a
            WHERE a.user_id = $1
            ORDER BY a.created_at DESC;
        `;
        const applicationsResult = await client.query(applicationsQuery, [user_id]);
        const applications = applicationsResult.rows;

        if (applications.length === 0) {
             res.status(200).json([]);
             return;
        }

        const familyMembersQuery = `
            SELECT id, application_id, name, surname, relationship, date_of_birth
            FROM public.family_members
            WHERE application_id = ANY($1::uuid[])
            ORDER BY application_id, id;
        `;
        const familyMembersResult = await client.query(familyMembersQuery, [applications.map(a => a.id)]);

        const extendedFamilyQuery = `
            SELECT id, application_id, name, surname, relationship, date_of_birth, premium
            FROM public.extended_family
            WHERE application_id = ANY($1::uuid[])
            ORDER BY application_id, id;
        `;
        const extendedFamilyResult = await client.query(extendedFamilyQuery, [applications.map(a => a.id)]);

        const familyMembersMap: Record<string, any[]> = {};
        for (const member of familyMembersResult.rows) {
            if (!familyMembersMap[member.application_id]) {
                familyMembersMap[member.application_id] = [];
            }
            familyMembersMap[member.application_id].push(member);
        }

        const extendedFamilyMap: Record<string, any[]> = {};
        for (const member of extendedFamilyResult.rows) {
            if (!extendedFamilyMap[member.application_id]) {
                extendedFamilyMap[member.application_id] = [];
            }
            extendedFamilyMap[member.application_id].push(member);
        }

        const combinedApplications = applications.map(app => ({
            ...app,
            family_members: familyMembersMap[app.id] || [],
            extended_family: extendedFamilyMap[app.id] || [],
        }));

        res.status(200).json(combinedApplications);

    } catch (error) {
        console.error('Error fetching applications:', error);
        res.status(500).json({ error: 'Failed to fetch applications.', details: error instanceof Error ? error.message : String(error) });
    } finally {
        client.release();
    }
});

// PATCH /api/applications/:id - Update an existing application
app.patch('/api/applications/:id', authMiddleware, async (req: Request, res: Response) => {
    const applicationId = req.params.id;
    if (!applicationId) {
        return res.status(400).json({ error: 'Application ID is required.' });
    }

    const updates: Partial<{
        name: string | null;
        surname: string | null;
        phone: string | null;
        email: string | null;
        address: string | null;
        nationality: string | null;
        gender: string | null;
        date_of_birth: string | null;
        id_number: string | null;
        alt_name: string | null;
        relation_to_member: string | null;
        relation_dob: string | null;
        plan_options: string | null;
        beneficiary_name: string | null;
        beneficiary_surname: string | null;
        beneficiary_contact: string | null;
        pay_options: string | null;
        total_amount: number | null;
        bank: string | null;
        branch_code: string | null;
        account_holder: string | null;
        account_number: string | null;
        deduction_date: string | null;
        account_type: string | null;
        commencement_date: string | null;
        declaration_signature: string | null;
        declaration_date: string | null;
        call_time: string | null;
        agent_name: string | null;
        connector_name: string | null;
        connector_contact: string | null;
        connector_province: string | null;
        team_leader: string | null;
        team_contact: string | null;
        team_province: string | null;
        // status: string | null; // Add if you have a status column
    }> = req.body;

    // Use parent_user_id for ownership check, consistent with GET/POST
    const userId = req.user!.parent_user_id;

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. Verify Application Ownership
        const ownershipCheck = await client.query(
            'SELECT id FROM public.applications WHERE id = $1 AND parent_user_id = $2', // Select ID for clarity, though COUNT(1) works too
            [applicationId, userId]
        );

        if (ownershipCheck.rowCount === 0 || ownershipCheck.rowCount === null) { // Check for null as well, though unlikely here
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Application not found or access denied.' });
        }

        // 2. Update Main Application Record
        const updateFields: string[] = [];
        const updateValues: any[] = [];
        let valueIndex = 1;

        const allowedUpdateFields = [
            'name', 'surname', 'phone', 'email', 'address', 'nationality', 'gender', 'date_of_birth', 'id_number',
            'alt_name', 'relation_to_member', 'relation_dob', 'plan_options', 'beneficiary_name', 'beneficiary_surname',
            'beneficiary_contact', 'pay_options', 'total_amount', 'bank', 'branch_code', 'account_holder',
            'account_number', 'deduction_date', 'account_type', 'commencement_date', 'declaration_signature',
            'declaration_date', 'call_time', 'agent_name', 'connector_name', 'connector_contact',
            'connector_province', 'team_leader', 'team_contact', 'team_province'
            // 'status' // Add if you have a status column
        ];

        for (const [key, value] of Object.entries(updates)) {
            if (allowedUpdateFields.includes(key)) {
                updateFields.push(`${key} = $${valueIndex}`);
                updateValues.push(value);
                valueIndex++;
            }
        }

        if (updateFields.length > 0) {
            const updateQuery = `
                UPDATE public.applications
                SET ${updateFields.join(', ')}, updated_at = NOW()
                WHERE id = $${valueIndex}
            `;
            updateValues.push(applicationId);

            await client.query(updateQuery, updateValues);
        } // else, no main fields to update, which is fine

        // 3. Handle Family Members
        if (Array.isArray(req.body.family_members)) {
            const providedFamilyMembers = req.body.family_members;

            const existingFamilyResult = await client.query(
                'SELECT id FROM public.family_members WHERE application_id = $1',
                [applicationId]
            );
            const existingFamilyIds = new Set(existingFamilyResult.rows.map(r => r.id));
            const providedFamilyIds = new Set<number>();
            const newFamilyMembers = [];
            const updatedFamilyMembers = [];

            for (const member of providedFamilyMembers) {
                // Type guard and check for valid ID
                if (member.id !== undefined && member.id !== null && typeof member.id === 'number') {
                    providedFamilyIds.add(member.id);
                    updatedFamilyMembers.push(member);
                } else {
                    // Assume it's a new member if ID is missing, null, or invalid
                    newFamilyMembers.push(member);
                }
            }

            // --- Delete family members not in the provided list ---
            const idsToDelete = [...existingFamilyIds].filter(id => !providedFamilyIds.has(id));
            if (idsToDelete.length > 0) {
                await client.query(
                    'DELETE FROM public.family_members WHERE id = ANY($1::int[])',
                    [idsToDelete]
                );
            }

            // --- Update existing family members ---
            for (const member of updatedFamilyMembers) {
                const checkQuery = 'SELECT 1 FROM public.family_members WHERE id = $1 AND application_id = $2';
                const checkResult = await client.query(checkQuery, [member.id, applicationId]);
                // --- FIXED: Check for null rowCount ---
                if (checkResult.rowCount !== null && checkResult.rowCount > 0) {
                    const updateFields: string[] = [];
                    const updateValues: any[] = [];
                    let idx = 1;
                    if (member.name !== undefined) { updateFields.push(`name = $${idx++}`); updateValues.push(member.name); }
                    if (member.surname !== undefined) { updateFields.push(`surname = $${idx++}`); updateValues.push(member.surname); }
                    if (member.relationship !== undefined) { updateFields.push(`relationship = $${idx++}`); updateValues.push(member.relationship); }
                    if (member.date_of_birth !== undefined) { updateFields.push(`date_of_birth = $${idx++}`); updateValues.push(member.date_of_birth); }

                    if(updateFields.length > 0) {
                        const updateQuery = `UPDATE public.family_members SET ${updateFields.join(', ')}, updated_at = NOW() WHERE id = $${idx}`;
                        updateValues.push(member.id);
                        await client.query(updateQuery, updateValues);
                    }
                } else {
                    console.warn(`Family member ID ${member.id} not found for application ${applicationId} or does not belong to it. Skipping update.`);
                    // Optionally, return a 400 error if trying to update a non-existent member ID
                    // return res.status(400).json({ error: `Family member ID ${member.id} not found for this application.` });
                }
            }

            // --- Insert new family members ---
            if (newFamilyMembers.length > 0) {
                // Using a transaction-safe multi-row insert
                const insertQuery = `
                    INSERT INTO public.family_members (application_id, name, surname, relationship, date_of_birth)
                    VALUES ($1, $2, $3, $4, $5)
                `;
                 // Prepare values for multi-row insert or loop
                 for (const member of newFamilyMembers) {
                     await client.query(insertQuery, [
                         applicationId,
                         member.name ?? null, // Ensure nulls are passed explicitly if fields are optional
                         member.surname ?? null,
                         member.relationship ?? null,
                         member.date_of_birth ?? null
                     ]);
                 }
            }
        }

        // 4. Handle Extended Family Members
        if (Array.isArray(req.body.extended_family)) {
            const providedExtendedFamilyMembers = req.body.extended_family;

            const existingExtendedFamilyResult = await client.query(
                'SELECT id FROM public.extended_family WHERE application_id = $1',
                [applicationId]
            );
            const existingExtendedFamilyIds = new Set(existingExtendedFamilyResult.rows.map(r => r.id));
            const providedExtendedFamilyIds = new Set<number>();
            const newExtendedFamilyMembers = [];
            const updatedExtendedFamilyMembers = [];

            for (const member of providedExtendedFamilyMembers) {
                 // Type guard and check for valid ID
                if (member.id !== undefined && member.id !== null && typeof member.id === 'number') {
                    providedExtendedFamilyIds.add(member.id);
                    updatedExtendedFamilyMembers.push(member);
                } else {
                    // Assume it's a new member if ID is missing, null, or invalid
                    newExtendedFamilyMembers.push(member);
                }
            }

            // --- Delete extended family members not in the provided list ---
            const idsToDelete = [...existingExtendedFamilyIds].filter(id => !providedExtendedFamilyIds.has(id));
            if (idsToDelete.length > 0) {
                await client.query(
                    'DELETE FROM public.extended_family WHERE id = ANY($1::int[])',
                    [idsToDelete]
                );
            }

            // --- Update existing extended family members ---
            for (const member of updatedExtendedFamilyMembers) {
                const checkQuery = 'SELECT 1 FROM public.extended_family WHERE id = $1 AND application_id = $2';
                const checkResult = await client.query(checkQuery, [member.id, applicationId]);
                // --- FIXED: Check for null rowCount ---
                if (checkResult.rowCount !== null && checkResult.rowCount > 0) {
                    const updateFields: string[] = [];
                    const updateValues: any[] = [];
                    let idx = 1;
                    if (member.name !== undefined) { updateFields.push(`name = $${idx++}`); updateValues.push(member.name); }
                    if (member.surname !== undefined) { updateFields.push(`surname = $${idx++}`); updateValues.push(member.surname); }
                    if (member.relationship !== undefined) { updateFields.push(`relationship = $${idx++}`); updateValues.push(member.relationship); }
                    if (member.date_of_birth !== undefined) { updateFields.push(`date_of_birth = $${idx++}`); updateValues.push(member.date_of_birth); }
                    if (member.premium !== undefined) { updateFields.push(`premium = $${idx++}`); updateValues.push(member.premium); }

                    if(updateFields.length > 0) {
                        const updateQuery = `UPDATE public.extended_family SET ${updateFields.join(', ')}, updated_at = NOW() WHERE id = $${idx}`;
                        updateValues.push(member.id);
                        await client.query(updateQuery, updateValues);
                    }
                } else {
                    console.warn(`Extended family member ID ${member.id} not found for application ${applicationId} or does not belong to it. Skipping update.`);
                    // Optionally, return a 400 error if trying to update a non-existent member ID
                    // return res.status(400).json({ error: `Extended family member ID ${member.id} not found for this application.` });
                }
            }

            // --- Insert new extended family members ---
            if (newExtendedFamilyMembers.length > 0) {
                 const insertQuery = `
                    INSERT INTO public.extended_family (application_id, name, surname, relationship, date_of_birth, premium)
                    VALUES ($1, $2, $3, $4, $5, $6)
                `;
                for (const member of newExtendedFamilyMembers) {
                    await client.query(insertQuery, [
                        applicationId,
                        member.name ?? null,
                        member.surname ?? null,
                        member.relationship ?? null,
                        member.date_of_birth ?? null,
                        member.premium ?? null // Handle potential null/undefined premium
                    ]);
                }
            }
        }

        await client.query('COMMIT');
        res.status(200).json({ message: 'Application updated successfully!', id: applicationId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error updating application:', error);
        // Provide more specific error messages where possible
        if (error instanceof Error && error.message.includes('duplicate key value violates unique constraint')) {
             res.status(409).json({ error: 'Conflict: Duplicate entry found.', details: error.message });
        } else {
             res.status(500).json({ error: 'Failed to update application.', details: error instanceof Error ? error.message : String(error) });
        }
    } finally {
        client.release();
    }
});
// Add this new endpoint to your server.ts file, e.g., after the quotes endpoint.
// --- NEW ENDPOINT: GET MY CLIENTS & SALES DATA ---
app.get('/api/my-clients', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.user_id;
  const client = await pool.connect();

  try {
    const myClientsQuery = `
      SELECT
          a.name AS client_name,
          a.surname AS client_surname,
          a.created_at AS application_date,
          s.total_amount AS sales_amount
      FROM
          public.applications AS a
      JOIN
          public.sales AS s ON a.agent_name = s.branch
      WHERE
          a.user_id = $1
      ORDER BY
          a.created_at DESC;
    `;
    
    const result = await client.query(myClientsQuery, [user_id]);
    
    // Format the data for the frontend
    const myClientsData = result.rows.map(row => ({
      clientName: `${row.client_name ?? ''} ${row.client_surname ?? ''}`.trim(),
      applicationDate: new Date(row.application_date).toLocaleDateString(),
      salesAmount: row.sales_amount ? parseFloat(row.sales_amount) : 0,
    }));

    res.status(200).json(myClientsData);

  } catch (error) {
    console.error('Error fetching my clients data:', error);
    res.status(500).json({ error: 'Failed to fetch clients and sales data.' });
  } finally {
    client.release();
  }
});



// New endpoint for Revenue by Product/Service
// Endpoint for Revenue by Product/Service using the sales table
// Endpoint for Revenue by Product/Service using the sales table
app.get('/api/charts/revenue-by-product', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.parent_user_id;
  const { startDate, endDate } = req.query;

  try {
    let dateFilter = '';
    const queryParams: (string | number)[] = [user_id];
    let paramIndex = 2;

    if (startDate) {
      dateFilter += ` AND s.created_at >= $${paramIndex++}`; // Use s.created_at for filtering
      queryParams.push(startDate as string);
    }
    if (endDate) {
      dateFilter += ` AND s.created_at <= $${paramIndex++}`; // Use s.created_at for filtering
      queryParams.push(endDate as string);
    }

    // Query to get aggregated revenue by product_name from public.sale_items, joined with public.sales
    const result = await pool.query(
      `SELECT si.product_name, COALESCE(SUM(si.subtotal), 0) AS total_revenue
       FROM public.sale_items si
       JOIN public.sales s ON si.sale_id = s.id
       WHERE s.user_id = $1 ${dateFilter}
       GROUP BY si.product_name
       ORDER BY total_revenue DESC;`,
      queryParams
    );

    // Format data for Pareto chart
    const paretoData = result.rows.map(row => ({
        id: `product-${row.product_name.replace(/\s+/g, '-').toLowerCase()}`,
        name: row.product_name,
        value: parseFloat(row.total_revenue),
    }));

    // Ensure the data is sorted for Pareto chart (descending order by value)
    paretoData.sort((a, b) => b.value - a.value);


    res.status(200).json(paretoData);

  } catch (error) {
    console.error('Error fetching revenue by product data from sales and sale_items tables:', error);
    res.status(500).json({ error: 'Failed to fetch revenue by product data.', details: error instanceof Error ? error.message : String(error) });
  }
});


// Prefer company scoping, fallback to user_id
const getUserId = (req: any): string | null =>
  (req.user?.parent_user_id || req.user?.user_id) ?? null;

// ---------------------- JOURNAL ENTRIES ----------------------

// Create
app.post("/journal-entries", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const { entryDate, memo, lines } = req.body || {};
  if (!entryDate || !Array.isArray(lines) || lines.length < 2) {
    return res.status(400).json({ error: "entryDate and at least two lines are required" });
  }

  // balance & line validation
  let dr = 0, cr = 0;
  for (const l of lines) {
    if (!l || typeof l.accountId !== "number") {
      return res.status(400).json({ error: "Each line needs accountId:number, debit/credit:number" });
    }
    const debit = Number(l.debit || 0), credit = Number(l.credit || 0);
    if (debit < 0 || credit < 0) return res.status(400).json({ error: "Debits/credits must be >= 0" });
    if (debit === 0 && credit === 0) return res.status(400).json({ error: "A line cannot be zero/zero" });
    if (debit > 0 && credit > 0) return res.status(400).json({ error: "A line cannot have both debit and credit" });
    dr += debit; cr += credit;
  }
  if (Math.abs(dr - cr) > 1e-6) return res.status(400).json({ error: "Entry not balanced (debits ≠ credits)" });

  const cx = await pool.connect();
  try {
    await cx.query("BEGIN");

    // validate accounts belong to this user and are postable/active/mapped
    const ids = [...new Set(lines.map((l: any) => l.accountId))];
    const accs = await cx.query(
      `SELECT id, is_postable, is_active, reporting_category_id
           FROM public.accounts
         WHERE user_id = $1 AND id = ANY($2::int[])`,
      [userId, ids]
    );
    if (accs.rows.length !== ids.length) throw new Error("One or more accounts do not belong to this user");
    const bad = accs.rows.find(a => !a.is_active || !a.is_postable || !a.reporting_category_id);
    if (bad) {
      if (!bad.is_active) throw new Error(`Account ${bad.id} is inactive`);
      if (!bad.is_postable) throw new Error(`Cannot post to a parent/summary account (${bad.id})`);
      throw new Error(`Account ${bad.id} has no reporting mapping`);
    }

    // insert entry
    const ins = await cx.query(
      `INSERT INTO public.journal_entries (entry_date, memo, user_id)
        VALUES ($1,$2,$3) RETURNING id, entry_date, memo`,
      [entryDate, memo ?? null, userId]
    );
    const entry = ins.rows[0];

    // bulk insert lines
    const values: string[] = [];
    const params: any[] = [];
    let i = 1;
    for (const l of lines) {
      values.push(`($${i++}, $${i++}, $${i++}, $${i++}, $${i++})`);
      params.push(entry.id, l.accountId, userId, Number(l.debit || 0), Number(l.credit || 0));
    }
    await cx.query(
      `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
        VALUES ${values.join(",")}`,
      params
    );

    const outLines = await cx.query(
      `SELECT id, account_id, debit, credit
           FROM public.journal_lines
         WHERE entry_id=$1 AND user_id=$2
         ORDER BY id`,
      [entry.id, userId]
    );

    await cx.query("COMMIT");
    res.status(201).json({ entry, lines: outLines.rows });
  } catch (err: any) {
    await cx.query("ROLLBACK");
    const msg = String(err?.message || err);
    if (msg.includes("not balanced")) return res.status(400).json({ error: "Entry not balanced" });
    return res.status(400).json({ error: msg });
  } finally {
    cx.release();
  }
});

// List
app.get("/journal-entries", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const { start, end, q } = req.query as any;

  const params: any[] = [userId];
  const where: string[] = ["je.user_id = $1"];
  if (start) { params.push(start); where.push(`je.entry_date >= $${params.length}`); }
  if (end)   { params.push(end);   where.push(`je.entry_date <= $${params.length}`); }
  if (q)     { params.push(`%${q}%`); where.push(`(je.memo ILIKE $${params.length})`); }

  const rows = await pool.query(
    `SELECT je.id, je.entry_date, je.memo,
            COALESCE(SUM(jl.debit),0) AS total_debit,
            COALESCE(SUM(jl.credit),0) AS total_credit,
            COUNT(jl.id) AS line_count
       FROM public.journal_entries je
  LEFT JOIN public.journal_lines jl ON jl.entry_id = je.id AND jl.user_id = je.user_id
      WHERE ${where.join(" AND ")}
   GROUP BY je.id
   ORDER BY je.entry_date DESC, je.id DESC`,
    params // No longer passing pageSize or offset
  );

  // The response now simply returns all items found, without pagination details.
  res.json({ items: rows.rows });
});


// Get one
app.get("/journal-entries/:id", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const id = Number(req.params.id);
  const e = await pool.query(
    `SELECT id, entry_date, memo
       FROM public.journal_entries
     WHERE id=$1 AND user_id=$2`,
    [id, userId]
  );
  if (!e.rows.length) return res.status(404).json({ error: "Not found" });

  const l = await pool.query(
    `SELECT id, account_id, debit, credit
       FROM public.journal_lines
     WHERE entry_id=$1 AND user_id=$2
     ORDER BY id`,
    [id, userId]
  );

  res.json({ entry: e.rows[0], lines: l.rows });
});

// Update (replace lines)
app.put("/journal-entries/:id", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const id = Number(req.params.id);
  const { entryDate, memo, lines } = req.body || {};
  if (!entryDate || !Array.isArray(lines) || lines.length < 2) {
    return res.status(400).json({ error: "entryDate and at least two lines are required" });
  }

  let dr = 0, cr = 0;
  for (const l of lines) {
    const debit = Number(l.debit || 0), credit = Number(l.credit || 0);
    if (debit < 0 || credit < 0) return res.status(400).json({ error: "Debits/credits must be >= 0" });
    if (debit === 0 && credit === 0) return res.status(400).json({ error: "A line cannot be zero/zero" });
    if (debit > 0 && credit > 0) return res.status(400).json({ error: "A line cannot have both debit and credit" });
    dr += debit; cr += credit;
  }
  if (Math.abs(dr - cr) > 1e-6) return res.status(400).json({ error: "Entry not balanced" });

  const cx = await pool.connect();
  try {
    await cx.query("BEGIN");

    // ensure entry belongs to user
    const upd = await cx.query(
      `UPDATE public.journal_entries
           SET entry_date=$1, memo=$2
         WHERE id=$3 AND user_id=$4`,
      [entryDate, memo ?? null, id, userId]
    );
    if (!upd.rowCount) {
      await cx.query("ROLLBACK");
      return res.status(404).json({ error: "Not found" });
    }

    // validate accounts
    const ids = [...new Set(lines.map((l: any) => l.accountId))];
    const accs = await cx.query(
      `SELECT id, is_postable, is_active, reporting_category_id
           FROM public.accounts
         WHERE user_id = $1 AND id = ANY($2::int[])`,
      [userId, ids]
    );
    if (accs.rows.length !== ids.length) throw new Error("One or more accounts do not belong to this user");
    const bad = accs.rows.find(a => !a.is_active || !a.is_postable || !a.reporting_category_id);
    if (bad) {
      if (!bad.is_active) throw new Error(`Account ${bad.id} is inactive`);
      if (!bad.is_postable) throw new Error(`Cannot post to a parent/summary account (${bad.id})`);
      throw new Error(`Account ${bad.id} has no reporting mapping`);
    }

    // replace lines
    await cx.query(`DELETE FROM public.journal_lines WHERE entry_id=$1 AND user_id=$2`, [id, userId]);

    const values: string[] = [];
    const params: any[] = [];
    let i = 1;
    for (const l of lines) {
      values.push(`($${i++}, $${i++}, $${i++}, $${i++}, $${i++})`);
      params.push(id, l.accountId, userId, Number(l.debit || 0), Number(l.credit || 0));
    }
    await cx.query(
      `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
        VALUES ${values.join(",")}`,
      params
    );

    const out = await cx.query(
      `SELECT id, account_id, debit, credit
           FROM public.journal_lines
         WHERE entry_id=$1 AND user_id=$2
         ORDER BY id`,
      [id, userId]
    );

    await cx.query("COMMIT");
    res.json({ entry: { id, entry_date: entryDate, memo: memo ?? null }, lines: out.rows });
  } catch (err: any) {
    await cx.query("ROLLBACK");
    res.status(400).json({ error: String(err?.message || err) });
  } finally {
    cx.release();
  }
});

// Delete
app.delete("/journal-entries/:id", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const id = Number(req.params.id);
  const del = await pool.query(
    `DELETE FROM public.journal_entries WHERE id=$1 AND user_id=$2`,
    [id, userId]
  );
  if (!del.rowCount) return res.status(404).json({ error: "Not found" });
  res.status(204).send();
});

// ---------------------- REPORTS ----------------------

// Income Statement (by period, indirect signs)
// GET /reports/income-statement?start=YYYY-MM-DD&end=YYYY-MM-DD
app.get("/reports/income-statement", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id;
  const start = req.query.start as string;
  const end = req.query.end as string;
  if (!start || !end) return res.status(400).json({ error: "start & end required" });

  try {
    const { rows } = await pool.query(
      `
      SELECT
        a.name AS account_name,
        rc.section AS reporting_section,
        a.normal_side AS normal_side,
        SUM(jl.debit - jl.credit) AS balance
      FROM
        public.journal_lines jl
      JOIN
        public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
      JOIN
        public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
      JOIN
        public.reporting_categories rc ON rc.id = a.reporting_category_id
      WHERE
        je.user_id = $1
        AND rc.statement = 'income_statement'
        AND je.entry_date BETWEEN $2::date AND $3::date
      GROUP BY
        a.name, rc.section, a.normal_side
      ORDER BY
        rc.section, a.name;
      `,
      [userId, start, end]
    );

    const sectionMap: Record<string, { section: string; amount: number; accounts: any[] }> = {};

    rows.forEach(row => {
      const sectionName = row.reporting_section;
      if (!sectionMap[sectionName]) {
        sectionMap[sectionName] = {
          section: sectionName,
          amount: 0,
          accounts: []
        };
      }
      
      const balance = parseFloat(row.balance);
      const amount = (row.normal_side === 'Credit') ? -balance : balance;

      sectionMap[sectionName].amount += amount;
      sectionMap[sectionName].accounts.push({
        name: row.account_name,
        amount: amount
      });
    });

    res.json({ period: { start, end }, sections: Object.values(sectionMap) });

  } catch (error) {
    console.error("Error fetching income statement:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Balance Sheet (as of date)
// GET /reports/balance-sheet?asOf=YYYY-MM-DD
// server.ts

app.get("/reports/balance-sheet", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id;
  const asOf = req.query.asOf as string;
  if (!asOf) return res.status(400).json({ error: "asOf required" });

  const client = await pool.connect();
  try {
    // --- 1. Calculate Net Profit/Loss for the period up to 'asOf' ---
    // This query sums all income statement items (revenue/other_income are credits, expenses are debits)
    // Using the correct sign based on normal side to get the final profit/loss figure.
    const profitLossResult = await client.query(
      `
      SELECT 
        SUM(CASE 
          WHEN a.normal_side = 'Credit' THEN (jl.credit - jl.debit) -- Revenue/Income
          ELSE -(jl.debit - jl.credit) -- Expenses (negate to subtract from income)
        END) AS net_profit_loss
      FROM public.journal_lines jl
      JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
      JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
      JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
      WHERE je.user_id = $1
        AND rc.statement = 'income_statement'
        AND je.entry_date <= $2::date
      `,
      [userId, asOf]
    );
    const netProfitLoss = parseFloat(profitLossResult.rows[0]?.net_profit_loss) || 0;
    // --- End Net Profit Calculation ---

    // --- 2. Get the standard Balance Sheet sections (Assets, Liabilities, base Equity) ---
    const { rows: balanceSheetSections } = await client.query(
      `
      SELECT rc.section,
             SUM(CASE a.normal_side
                   WHEN 'Debit'   THEN (jl.debit - jl.credit)
                   ELSE            -(jl.debit - jl.credit)
                 END) AS value
        FROM public.journal_lines jl
        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
        JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
       WHERE je.user_id = $1
         AND rc.statement = 'balance_sheet'
         AND je.entry_date <= $2::date
       GROUP BY rc.section
       ORDER BY rc.section
      `,
      [userId, asOf]
    );
    // --- End Standard Sections ---

    // --- 3. Get the Opening Balance Equity specifically ---
    // Find the account ID for 'Opening Balance Equity'
    const obeAccountResult = await client.query(
      `SELECT id FROM public.accounts WHERE user_id = $1 AND name = 'Opening Balance Equity' LIMIT 1`,
      [userId]
    );
    let openingBalanceEquityValue = 0;
    if (obeAccountResult.rows.length > 0) {
      const obeAccountId = obeAccountResult.rows[0].id;
      const obeBalanceResult = await client.query(
        `
        SELECT 
          SUM(CASE a.normal_side
                WHEN 'Debit' THEN (jl.debit - jl.credit)
                ELSE          -(jl.debit - jl.credit)
              END) AS balance
        FROM public.journal_lines jl
        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
        WHERE jl.user_id = $1
          AND jl.account_id = $2
          AND je.entry_date <= $3::date
        `,
        [userId, obeAccountId, asOf]
      );
      openingBalanceEquityValue = parseFloat(obeBalanceResult.rows[0]?.balance) || 0;
    }
    // --- End Opening Balance Equity ---

    // --- 4. Prepare the final response data ---
    // Organize the standard sections for easy access
    const sectionsMap: Record<string, number> = {};
    balanceSheetSections.forEach(s => {
        sectionsMap[s.section] = parseFloat(s.value) || 0;
    });

    // Calculate the derived equity values
    const retainedEarningsOrSimilarEquity = sectionsMap['equity'] || 0; // This might include OBE + some retained earnings if manually adjusted
    // More accurate closing equity: Opening OBE + Net Profit (This is the key calculation)
    const closingEquity = openingBalanceEquityValue + netProfitLoss; 

    // Send back all necessary data for the frontend to build the desired structure
    res.json({ 
      asOf, 
      sections: balanceSheetSections, // Standard sections from reporting categories
      openingEquity: openingBalanceEquityValue,
      netProfitLoss: netProfitLoss,
      closingEquity: closingEquity,
      // Also pass raw values for assets/liabilities for totals if needed
      assets: {
        current: sectionsMap['current_assets'] || 0,
        non_current: sectionsMap['non_current_assets'] || 0
      },
      liabilities: {
        current: sectionsMap['current_liabilities'] || 0,
        non_current: sectionsMap['non_current_liabilities'] || 0
      }
    });

  } catch (err) {
    console.error("Error generating balance sheet:", err);
    res.status(500).json({ error: "Failed to generate balance sheet" });
  } finally {
    client.release();
  }
});

// Cash Flow (Indirect)
// GET /reports/cash-flow?start=YYYY-MM-DD&end=YYYY-MM-DD
// Cash Flow (Indirect)
// GET /reports/cash-flow?start=YYYY-MM-DD&end=YYYY-MM-DD
app.get("/reports/cash-flow", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id;
  const start = req.query.start as string;
  const end = req.query.end as string;
  if (!start || !end) return res.status(400).json({ error: "start & end required" });

  try {
    // Direct query approach with corrected column names
    const { rows } = await pool.query(
      `
      WITH cash_changes AS (
        -- Operating: Net Income
        SELECT 
          'operating' as section,
          'Net Income' as line,
          SUM(CASE 
            WHEN a.normal_side = 'Debit' THEN (jl.credit - jl.debit)
            ELSE (jl.debit - jl.credit)
          END) as amount
        FROM public.journal_lines jl
        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
        JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
        WHERE je.user_id = $1
          AND rc.statement = 'income_statement'
          AND je.entry_date BETWEEN $2::date AND $3::date
      
        UNION ALL
      
        -- Operating: Depreciation
        SELECT 
          'operating' as section,
          'Depreciation' as line,
          SUM(CASE 
            WHEN a.normal_side = 'Debit' THEN (jl.debit - jl.credit)
            ELSE (jl.credit - jl.debit)
          END) as amount
        FROM public.journal_lines jl
        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
        WHERE je.user_id = $1
          AND a.name ILIKE '%depreciation%'
          AND je.entry_date BETWEEN $2::date AND $3::date
      
        UNION ALL
      
        -- Investing: Purchase of Assets
        SELECT 
          'investing' as section,
          'Purchase of Fixed Assets' as line,
          SUM(CASE 
            WHEN a.normal_side = 'Debit' THEN (jl.debit - jl.credit)
            ELSE (jl.credit - jl.debit)
          END) as amount
        FROM public.journal_lines jl
        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
        WHERE je.user_id = $1
          AND a.type = 'Asset'
          AND je.entry_date BETWEEN $2::date AND $3::date
      
        UNION ALL
      
        -- Financing: Loan Proceeds
        SELECT 
          'financing' as section,
          'Loan Proceeds' as line,
          SUM(CASE 
            WHEN a.normal_side = 'Credit' THEN (jl.credit - jl.debit)
            ELSE (jl.debit - jl.credit)
          END) as amount
        FROM public.journal_lines jl
        JOIN public.journal_entries je ON je.id = jl.entry_id AND je.user_id = jl.user_id
        JOIN public.accounts a ON a.id = jl.account_id AND a.user_id = jl.user_id
        WHERE je.user_id = $1
          AND a.type = 'Liability'
          AND je.entry_date BETWEEN $2::date AND $3::date
      )
      
      SELECT section, line, COALESCE(amount, 0) as amount
      FROM cash_changes
      WHERE amount != 0
      ORDER BY section, line
      `,
      [userId, start, end]
    );

    // Group for nicer JSON
    const grouped: Record<string, { line: string; amount: number }[]> = {};
    for (const r of rows) {
      grouped[r.section] = grouped[r.section] || [];
      grouped[r.section].push({ line: r.line, amount: parseFloat(r.amount.toString()) });
    }
    
    // Add totals for each section
    for (const section in grouped) {
      const total = grouped[section].reduce((sum, item) => sum + item.amount, 0);
      grouped[section].push({
        line: `Net Cash from ${section.charAt(0).toUpperCase() + section.slice(1)} Activities`,
        amount: total
      });
    }

    // Calculate final net increase/decrease in cash
    const netCash = Object.values(grouped).reduce((total, section) => {
      const lastItem = section[section.length - 1];
      return total + lastItem.amount;
    }, 0);

    res.json({ 
      period: { start, end }, 
      sections: grouped,
      netIncreaseInCash: netCash
    });
  } catch (error) {
    console.error("Cash flow error:", error);
    res.status(500).json({ error: "Failed to generate cash flow statement" });
  }
});
app.get("/reports/trial-balance", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const start = req.query.start as string;
  const end = req.query.end as string;
  const includeZero = String(req.query.includeZero || "false").toLowerCase() === "true";
  if (!start || !end) return res.status(400).json({ error: "start & end required" });

  // For the period, sum debits/credits per account.
  // Then compute display-side balance: show positive balance on the account's normal side.
  const { rows } = await pool.query(
    `
WITH period AS (
  SELECT
    a.id   AS account_id,
    a.code,
    a.name,
    a.type,
    COALESCE(SUM(jl.debit),  0)::numeric(18,2) AS total_debit,
    COALESCE(SUM(jl.credit), 0)::numeric(18,2) AS total_credit
  FROM public.accounts a
  LEFT JOIN public.journal_lines jl
    ON jl.account_id = a.id
   AND jl.user_id    = a.user_id
  LEFT JOIN public.journal_entries je
    ON je.id      = jl.entry_id
   AND je.user_id = jl.user_id
  WHERE a.user_id = $1
    AND (je.entry_date BETWEEN $2::date AND $3::date OR je.entry_date IS NULL)
  GROUP BY a.id, a.code, a.name, a.type
)
SELECT
  account_id, code, name, type,
  total_debit,
  total_credit,
  GREATEST(total_debit - total_credit, 0)::numeric(18,2) AS balance_debit,
  GREATEST(total_credit - total_debit, 0)::numeric(18,2) AS balance_credit
FROM period
ORDER BY code::text, name::text;


    `,
    [userId, start, end]
  );

  // optionally hide zero rows (no debits/credits and zero balance)
  const items = includeZero
    ? rows
    : rows.filter(r =>
        Number(r.total_debit) !== 0 ||
        Number(r.total_credit) !== 0 ||
        Number(r.balance_debit) !== 0 ||
        Number(r.balance_credit) !== 0
      );

  // grand totals (should match: total_debit == total_credit and balance_debit == balance_credit)
  const totals = items.reduce(
    (t, r) => {
      t.total_debit += Number(r.total_debit);
      t.total_credit += Number(r.total_credit);
      t.balance_debit += Number(r.balance_debit);
      t.balance_credit += Number(r.balance_credit);
      return t;
    },
    { total_debit: 0, total_credit: 0, balance_debit: 0, balance_credit: 0 }
  );

  res.json({
    period: { start, end },
    totals,
    items
  });
});

app.post("/imports/bank/stage", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id; // Access user from req.user
  const { source, rows } = req.body || {};
  if (!source || !Array.isArray(rows) || rows.length === 0)
    return res.status(400).json({ error: "source and rows[] required" });

  const cx = await pool.connect();
  try {
    await cx.query("BEGIN");
const b = await cx.query(
  `INSERT INTO public.import_batches (user_id, source)
   VALUES ($1,$2) RETURNING id, created_at, status`,
  [userId, source]
);
const batch = b.rows[0];

let inserted = 0, duplicates = 0;

for (const r of rows) {
  // assume you have a unique constraint on (user_id, source_uid)
  // e.g. CREATE UNIQUE INDEX import_rows_user_source_uid_uniq ON public.import_rows(user_id, source_uid);
  const q = await cx.query(
    `INSERT INTO public.import_rows
       (batch_id, user_id, source_uid, txn_date, description, amount)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (user_id, source_uid) DO NOTHING`,
    [batch.id, userId, r.sourceUid, r.date, r.description ?? null, Number(r.amount)]
  );
  if (q.rowCount === 0) duplicates++; else inserted++;
}

await cx.query("COMMIT");
res.status(201).json({ batchId: batch.id, inserted, duplicates });
  } catch (e: any) {
    await cx.query("ROLLBACK");
    res.status(400).json({ error: String(e?.message || e) });
  } finally {
    cx.release();
  }
});

// naive mapping helpers
// --- Add these helper functions near the top of your file, outside the endpoint handler ---

// --- Add these helper functions near the top of your file, outside the endpoint handler ---
// Make sure to add the necessary imports for Request, Response, and PoolClient if not already present
// import { Request, Response } from 'express';
// import { PoolClient } from 'pg'; // Or wherever PoolClient is imported from
// --- Add these helper functions near the top of your file, outside the endpoint handler ---
// Make sure to add the necessary imports for Request, Response, and PoolClient if not already present
// import { Request, Response } from 'express';
// import { PoolClient } from 'pg'; // Or wherever PoolClient is imported from

// Helper function to check if a string contains any keywords (case insensitive)
function includesAny(text: string, keywords: string[]): boolean {
  if (!text || !keywords || !Array.isArray(keywords)) return false;
  const lowerText = text.toLowerCase().trim();
  return keywords.some(keyword => 
    lowerText.includes(keyword.toLowerCase().trim())
  );
}

// Helper function to find an account by name keywords and type, mimicking frontend logic
// This function now tries to find the best match based on keyword priority and account name length
function findAccountByName(accounts: any[], keywords: string[], expectedType: string): any | null {
  if (!accounts || !Array.isArray(accounts) || !keywords || !expectedType) {
    return null;
  }

  const lowerExpectedType = expectedType.toLowerCase().trim();
  
  // Sort keywords by length descending for better matching (e.g., prefer longer, more specific names)
  const sortedKeywords = [...keywords]
    .filter(k => typeof k === 'string')
    .sort((a, b) => b.length - a.length);

  for (const keyword of sortedKeywords) {
    // 1. Try exact match first (case insensitive)
    let foundAccount = accounts.find(acc =>
      acc.name && acc.name.toLowerCase().trim() === keyword.toLowerCase().trim() &&
      acc.type && acc.type.toLowerCase().trim() === lowerExpectedType &&
      acc.is_active && acc.is_postable
    );

    if (foundAccount) {
      return foundAccount;
    }

    // 2. Try contains match (case insensitive)
    foundAccount = accounts.find(acc =>
      acc.name && acc.name.toLowerCase().includes(keyword.toLowerCase().trim()) &&
      acc.type && acc.type.toLowerCase().trim() === lowerExpectedType &&
      acc.is_active && acc.is_postable
    );

    if (foundAccount) {
      return foundAccount;
    }
  }

  // 3. If no specific keyword match, find any account of the expected type
  // This mimics some fallback logic seen in the frontend
  const anyOfType = accounts.find(acc =>
    acc.type && acc.type.toLowerCase().trim() === lowerExpectedType &&
    acc.is_active && acc.is_postable
  );
  
  return anyOfType || null;
}

// --- Replicated suggestAccountForText logic from ImportScreen.tsx ---
// This is the core function that matches the frontend's sophistication
const suggestAccountForImportRow = (description: string, amount: number, accounts: any[]) => {
  // --- Input validation ---
  if (typeof description !== 'string' || typeof amount !== 'number' || !Array.isArray(accounts)) {
    console.warn('Invalid inputs to suggestAccountForImportRow:', { description, amount, accountsType: typeof accounts });
    return { debitAccountId: null, creditAccountId: null, confidence: 0 };
  }

  const lowerDescription = description.toLowerCase().trim();
  const isOutflow = amount < 0;
  // const absAmount = Math.abs(amount); // Not used in current logic

  let debitAccount = null;
  let creditAccount = null;
  let confidence = 0;

  // --- INCOME (Money coming IN) ---
  if (!isOutflow) {
    confidence = 85; // Base confidence for income

    // --- Specific Income Category Matching (High Confidence) ---
    // Matches frontend logic for specific income types
    if (includesAny(lowerDescription, ['interest income', 'interest received'])) {
      creditAccount = findAccountByName(accounts, ['interest income'], 'income');
      if (creditAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['investment income', 'dividend', 'capital gains'])) {
      creditAccount = findAccountByName(accounts, ['investment income'], 'income');
      if (creditAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['rental income', 'lease income'])) {
      creditAccount = findAccountByName(accounts, ['rental income'], 'income');
      if (creditAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['commission income'])) {
      creditAccount = findAccountByName(accounts, ['commission income'], 'income');
      if (creditAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['service fee income', 'service fees'])) {
      creditAccount = findAccountByName(accounts, ['service fee income'], 'income');
      if (creditAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['other income'])) {
       creditAccount = findAccountByName(accounts, ['other income'], 'income');
       if (creditAccount) confidence = 90;
    }

    // --- Default Income (Lower Confidence Fallbacks) ---
    if (!creditAccount) {
      // Try Sales Revenue (very common)
      creditAccount = findAccountByName(accounts, ['sales revenue', 'revenue'], 'income');
      if (creditAccount) {
         confidence = 90; // High confidence for common revenue
      } else {
         // Fallback to any income account
         creditAccount = accounts.find((acc: any) => acc.type && acc.type.toLowerCase() === 'income' && acc.is_active && acc.is_postable);
         confidence = 85; // Base confidence
      }
    }

    // Debit side for income is usually Bank/Cash
    debitAccount = findAccountByName(accounts, ['bank account', 'bank', 'cheque account', 'cash'], 'asset');
    if (!debitAccount) {
       // Fallback to any asset account
       debitAccount = accounts.find((acc: any) => acc.type && acc.type.toLowerCase() === 'asset' && acc.is_active && acc.is_postable);
    }

  }
  // --- EXPENSES/OUTFLOWS (Money going OUT) ---
  else {
    confidence = 85; // Base confidence for expense

    // --- Specific Expense Category Matching (High Confidence) ---
    // These blocks replicate the extensive if/else logic from suggestAccountForText
    
    // Professional Services & Fees
    if (includesAny(lowerDescription, ['accounting fees', 'audit fees', 'legal fees', 'consulting fees'])) {
        debitAccount = findAccountByName(accounts, ['accounting fees expense', 'professional services expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['advertising', 'marketing', 'promotion', 'ads'])) {
        debitAccount = findAccountByName(accounts, ['advertising expense', 'marketing expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['bank charges', 'bank fees', 'service fees', 'transaction fees'])) {
        debitAccount = findAccountByName(accounts, ['bank charges & fees expense', 'service fees expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['communication', 'internet', 'telephone', 'cellphone', 'data', 'wifi'])) {
        debitAccount = findAccountByName(accounts, ['computer internet and telephone expense', 'communication expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['insurance', 'premium'])) {
        debitAccount = findAccountByName(accounts, ['insurance expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['interest expense', 'loan interest'])) {
        debitAccount = findAccountByName(accounts, ['interest expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['it services', 'software', 'website'])) {
        debitAccount = findAccountByName(accounts, ['it services & software expense', 'software expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['maintenance', 'repair', 'servicing'])) {
        debitAccount = findAccountByName(accounts, ['maintenance & repairs expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['office supplies', 'stationery', 'printing'])) {
        debitAccount = findAccountByName(accounts, ['office supplies expense', 'stationery expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['rent', 'lease'])) {
        debitAccount = findAccountByName(accounts, ['rent & lease expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['salary', 'wages', 'payroll', 'benefits'])) {
        debitAccount = findAccountByName(accounts, ['salaries and wages expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['tax', 'vat', 'income tax', 'corporate tax'])) {
        debitAccount = findAccountByName(accounts, ['tax expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['travel', 'airfare', 'hotel', 'uber', 'lyft', 'taxi', 'mileage'])) {
        debitAccount = findAccountByName(accounts, ['travel expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['utilities', 'electricity', 'water', 'gas'])) {
        debitAccount = findAccountByName(accounts, ['utilities expense', 'water and electricity expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['vehicle', 'fuel', 'petrol', 'diesel', 'car maintenance'])) {
        debitAccount = findAccountByName(accounts, ['vehicle expense', 'fuel expense'], 'expense');
        if (debitAccount) confidence = 95;
    } else if (includesAny(lowerDescription, ['entertainment', 'meal', 'dining', 'client lunch'])) {
        debitAccount = findAccountByName(accounts, ['entertainment expense', 'meals and entertainment expense'], 'expense');
        if (debitAccount) confidence = 90;
    } else if (includesAny(lowerDescription, ['project', 'materials', 'contractor'])) {
         debitAccount = findAccountByName(accounts, ['projects expenses'], 'expense');
         if (debitAccount) confidence = 90;
    } else if (includesAny(lowerDescription, ['website hosting', 'domain'])) {
         debitAccount = findAccountByName(accounts, ['website hosting fees'], 'expense');
         if (debitAccount) confidence = 90;
    }

    // --- Default Expense (Lower Confidence Fallbacks) ---
    if (!debitAccount) {
      // Try Miscellaneous Expense (common fallback)
      debitAccount = findAccountByName(accounts, ['miscellaneous expense', 'general expense'], 'expense');
      if (debitAccount) {
         confidence = 90; // High confidence for common fallback
      } else {
         // Fallback to any expense account
         debitAccount = accounts.find((acc: any) => acc.type && acc.type.toLowerCase() === 'expense' && acc.is_active && acc.is_postable);
         confidence = 85; // Base confidence
      }
    }

    // Credit side for expenses is usually Bank/Cash
    creditAccount = findAccountByName(accounts, ['bank account', 'bank', 'cheque account', 'cash'], 'asset');
    if (!creditAccount) {
       // Fallback to any asset account
       creditAccount = accounts.find((acc: any) => acc.type && acc.type.toLowerCase() === 'asset' && acc.is_active && acc.is_postable);
    }
  }

  // --- Final Validation ---
  // Ensure we have valid account objects and extract IDs
  const debitAccountId = debitAccount && typeof debitAccount.id !== 'undefined' ? Number(debitAccount.id) : null;
  const creditAccountId = creditAccount && typeof creditAccount.id !== 'undefined' ? Number(creditAccount.id) : null;

  // If one account is missing, the suggestion is incomplete
  if (!debitAccountId || !creditAccountId) {
    console.warn(`suggestAccountForImportRow: Could not find both accounts for "${description}". Debit: ${debitAccountId}, Credit: ${creditAccountId}`);
    // We might still return partial results with lower confidence if only one was found
    // but it's safer to return nulls if the match is incomplete for a double-entry system.
    // The preview UI can then show an error/warning.
    // Returning the found IDs with low confidence might be an alternative.
    // For now, let's be strict.
    // return { debitAccountId: null, creditAccountId: null, confidence: 0 };
    // Let's return what we found, but log the issue.
    confidence = Math.max(0, confidence - 20); // Reduce confidence for incomplete matches
  }

  return {
    debitAccountId,
    creditAccountId,
    confidence // Return confidence for potential UI display
  };
};
// --- End Replicated Logic ---

// --- Keep the existing findAccountId helper function (used minimally as a last resort fallback) ---
// Update the function signature with types
// Make sure to import PoolClient from 'pg'
async function findAccountId(cx: PoolClient, userId: string, name: string): Promise<number | null> {
  // Use ILIKE for more robust case-insensitive matching
  const q = await cx.query(
    `SELECT id FROM public.accounts 
     WHERE user_id=$1 AND name ILIKE $2 AND is_postable=true AND is_active=true 
     LIMIT 1`,
    [userId, name]
  );
  return q.rows[0]?.id ? Number(q.rows[0].id) : null;
}

// --- Modified /imports/:batchId/preview endpoint ---
// Make sure the endpoint signature matches your existing pattern, e.g.:
// app.get("/imports/:batchId/preview", authMiddleware, async (req: Request, res: Response) => {
app.get("/imports/:batchId/preview", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id;
  const batchId = Number(req.params.batchId);

  // Basic validation
  if (isNaN(batchId)) {
    return res.status(400).json({ error: "Invalid batch ID" });
  }

  const cx = await pool.connect(); // Assuming 'pool' is your pg Pool instance
  try {
    // Load staged rows
    const { rows } = await cx.query(
      `SELECT id, source_uid, txn_date, description, amount, is_duplicate, proposed_debit_account_id, proposed_credit_account_id
       FROM public.import_rows
       WHERE batch_id=$1 AND user_id=$2
       ORDER BY txn_date, id`,
      [batchId, userId]
    );

    // Fetch user's active and postable accounts ONCE for efficiency
    // This query matches the fields needed by findAccountByName
    const userAccountsResult = await cx.query(
      `SELECT id, name, type, is_active, is_postable
       FROM public.accounts
       WHERE user_id = $1 AND is_active = true AND is_postable = true`,
      [userId]
    );
    const userAccounts = userAccountsResult.rows;

    const out = [];
    for (const r of rows) {
      let debitId = r.proposed_debit_account_id ? Number(r.proposed_debit_account_id) : null;
      let creditId = r.proposed_credit_account_id ? Number(r.proposed_credit_account_id) : null;
      // let confidence = 0; // To potentially pass back confidence info // Removed as not used in response and causes type issues

      // Only use smart suggestion if no manual override exists
      if (!debitId || !creditId) {
        try {
          // Use the new smart suggestion logic that replicates the frontend
          const suggested = suggestAccountForImportRow(r.description || "", Number(r.amount), userAccounts);
          
          // Apply suggestions only if they improve upon existing null values or overrides
          // This allows for partial overrides (e.g., only debit was set manually)
          if (!debitId) {
            debitId = suggested.debitAccountId;
          }
          if (!creditId) {
            creditId = suggested.creditAccountId;
          }
          // confidence = suggested.confidence || 0; // Capture confidence if needed internally

          // Optional: Log if the smart suggestion failed but we had overrides
          if ((!debitId || !creditId) && (r.proposed_debit_account_id || r.proposed_credit_account_id)) {
             console.warn(`Preview: Smart suggestion failed for row ${r.id}, but manual override was incomplete.`);
          }
          
        } catch (suggestError: any) { // Explicitly type the error
          console.error(`Error during smart suggestion for row ${r.id}:`, suggestError);
          // Don't fail the whole preview, just log and potentially use fallback
        }
      } else {
        // If both are manually overridden, confidence is considered high (user input)
        // confidence = 95; // Not used
      }

      // Final fallback if smart suggestion and overrides failed, use the old method for critical accounts
      // This is a safety net, though the new logic should cover most cases.
      // It's kept minimal to avoid the original "Miscellaneous Expense" problem.
      if (!debitId || !creditId) {
         console.warn(`Row ${r.id} still missing account IDs after smart suggestion and overrides. Applying minimal fallback.`);
         // Only try to find Bank Account as a last resort for one side if missing
         if (!debitId && creditId) {
            const bankAcc = findAccountByName(userAccounts, ['bank account', 'bank', 'cheque account', 'cash'], 'asset');
            debitId = bankAcc ? Number(bankAcc.id) : null;
         } else if (debitId && !creditId) {
            const bankAcc = findAccountByName(userAccounts, ['bank account', 'bank', 'cheque account', 'cash'], 'asset');
            creditId = bankAcc ? Number(bankAcc.id) : null;
         }
         // If both are missing, we leave them null and let the frontend show an error.
         // confidence = Math.max(0, confidence - 30); // Significant confidence drop // Not used
      }

      // --- NEW: Save the calculated suggestions back to the database row ---
      // Only update if we have valid IDs and they differ from what's already stored
      // This ensures manual overrides from PATCH /imports/rows/:id are preserved
      // and smart suggestions are saved for use by /commit
      try {
        const updates: string[] = [];
        const updateParams: any[] = [r.id, userId]; // Start params with rowId and userId
        let paramIndex = 3; // Next placeholder will be $3

        // Check if we found a debitId and it's different from what's stored
        const currentDebitId = r.proposed_debit_account_id ? Number(r.proposed_debit_account_id) : null;
        if (debitId !== null && debitId !== currentDebitId) {
          updates.push(`proposed_debit_account_id = $${paramIndex}`);
          updateParams.push(debitId);
          paramIndex++;
        }

        // Check if we found a creditId and it's different from what's stored
        const currentCreditId = r.proposed_credit_account_id ? Number(r.proposed_credit_account_id) : null;
        if (creditId !== null && creditId !== currentCreditId) {
          updates.push(`proposed_credit_account_id = $${paramIndex}`);
          updateParams.push(creditId);
          // paramIndex++; // Not strictly needed if this is the last one, but good practice
        }

        // Only perform the update if there's something to change
        if (updates.length > 0) {
          const updateQuery = `
            UPDATE public.import_rows
            SET ${updates.join(', ')}
            WHERE id = $1 AND user_id = $2
          `;
          await cx.query(updateQuery, updateParams);
          // Optional: Log successful updates for debugging
          // console.log(`Updated proposed accounts for row ${r.id}: Debit=${debitId}, Credit=${creditId}`);
        }
      } catch (updateError: any) {
        console.error(`Error updating proposed accounts for row ${r.id}:`, updateError);
        // Depending on desired robustness, you might want to continue with the preview
        // even if one row fails to update, or return an error.
        // For now, we'll log and continue.
      }
      // --- End of saving suggestions to DB ---

      out.push({
        rowId: r.id,
        sourceUid: r.source_uid,
        date: r.txn_date,
        description: r.description,
        amount: Number(r.amount),
        suggested: { 
          debitAccountId: debitId, 
          creditAccountId: creditId
          // Removed confidence field to avoid type issues
        },
        duplicate: r.is_duplicate || false,
        error: (!debitId || !creditId) ? "Missing mapped accounts. Please review and assign accounts." : null
      });
    }

    res.json({ batchId, items: out });
  } catch (error: any) { // Explicitly type the error
    console.error("Error in /imports/:batchId/preview:", error);
    // Access error.message safely after typing 'error' as 'any'
    // Use 'instanceof Error' for better type safety if possible
    res.status(500).json({ 
      error: "Failed to generate preview", 
      detail: error instanceof Error ? error.message.substring(0, 200) : "Unknown error"
    });
  } finally {
    try {
      cx.release(); // Ensure connection is released
    } catch (releaseError) {
      console.warn("Error releasing database connection:", releaseError);
    }
  }
});
// --- End Modified Endpoint ---

// --- Keep the existing guessAccounts helper function (used minimally as a last resort fallback) ---
// Note: This is intentionally left simple, as the main logic is now in suggestAccountForImportRow
// Update the function signature with types
function guessAccounts(desc: string, amount: number) {
  const d = (desc || "").toLowerCase();
  if (amount > 0) {
    return { debit: "Bank Account", credit: d.includes("interest") ? "Interest Income" : "Sales Revenue" };
  } else {
    if (d.includes("fuel")) return { debit: "Fuel Expense", credit: "Bank Account" };
    if (d.includes("rent")) return { debit: "Rent Expense", credit: "Bank Account" };
    if (d.includes("salary") || d.includes("wage")) return { debit: "Salaries and Wages Expense", credit: "Bank Account" };
    if (d.includes("accounting")) return { debit: "Accounting Fees Expense", credit: "Bank Account" };
    // Default fallback - this is the problematic one we're trying to avoid
    return { debit: "Miscellaneous Expense", credit: "Bank Account" };
  }
}

app.post("/imports/:batchId/commit", authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id;
  const batchId = Number(req.params.batchId);

  const cx = await pool.connect();
  try {
    await cx.query("BEGIN");

    const b = await cx.query(
      `SELECT id, status
         FROM public.import_batches
        WHERE id=$1 AND user_id=$2
        FOR UPDATE`,
      [batchId, userId]
    );
    if (!b.rows.length) throw new Error("Batch not found");
    if (b.rows[0].status === "committed") {
      await cx.query("ROLLBACK");
      return res.status(200).json({ message: "Already committed", batchId });
    }

    const { rows } = await cx.query(
      `SELECT r.*
         FROM public.import_rows r
        WHERE r.batch_id=$1 AND r.user_id=$2
        ORDER BY r.txn_date, r.id`,
      [batchId, userId]
    );

    let posted = 0, skipped = 0;

    // --- NEW: Prepare data for transactions table ---
    const transactionsToInsert: Array<{
      user_id: string;
      type: 'income' | 'expense';
      amount: number;
      description: string;
      date: string; // Use the transaction_date from import_row or created_at
      category: string; // Use the mapped category or a default
      account_id: number | null; // Use the primary account (debit or credit) from the import
      original_text: string; // Use the original description from import_row
      source: string; // Indicate it came from import
      confirmed: boolean; // Set to true as it's committed
    }> = [];
    // --- END NEW ---

    for (const r of rows) {
      const rawAmt = Number(r.amount) || 0;
      const amtAbs = Math.abs(rawAmt);
      const isInflow = rawAmt >= 0;

      // CASE A: user gave both sides explicitly → use as-is (your original behavior)
      if (r.proposed_debit_account_id && r.proposed_credit_account_id) {
        const je = await cx.query(
          `INSERT INTO public.journal_entries (entry_date, memo, user_id)
             VALUES ($1,$2,$3) RETURNING id`,
          [r.txn_date, r.description ?? 'Imported', userId]
        );
        const entryId = je.rows[0].id;

        const lines: Array<{ entryId:number; accountId:number; debit:number; credit:number }> = [
          { entryId, accountId: r.proposed_debit_account_id,  debit: amtAbs, credit: 0 },
          { entryId, accountId: r.proposed_credit_account_id, debit: 0,     credit: amtAbs },
        ];

        // Optional VAT line (unchanged)
        if (r.proposed_vat_account_id && Number(r.proposed_vat_amount || 0) !== 0) {
          const vatAmt = Number(r.proposed_vat_amount);
          lines.push({
            entryId,
            accountId: r.proposed_vat_account_id,
            debit:  vatAmt > 0 ? vatAmt : 0,
            credit: vatAmt < 0 ? -vatAmt : 0,
          });
        }

        // bulk insert lines
        const values: string[] = [];
        const params: any[] = [];
        let i = 1;
        for (const l of lines) {
          values.push(`($${i++}, $${i++}, $${i++}, $${i++}, $${i++})`);
          params.push(l.entryId, l.accountId, userId, l.debit, l.credit);
        }
        await cx.query(
          `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
           VALUES ${values.join(",")}`,
          params
        );

        // --- NEW: Prepare transaction data for insertion ---
        // Determine primary account and type for transactions table
        const primaryAccountId = isInflow ? r.proposed_credit_account_id : r.proposed_debit_account_id;
        const transactionType: 'income' | 'expense' = isInflow ? 'income' : 'expense';
        
        // Determine category (this can be refined)
        let category = 'Imported'; // Default category
        if (primaryAccountId) {
            // Fetch account name/type to determine a better category
            const accountRes = await cx.query('SELECT name, type FROM public.accounts WHERE id = $1 AND user_id = $2', [primaryAccountId, userId]);
            if (accountRes.rows.length > 0) {
                const account = accountRes.rows[0];
                // Map account types/names to transaction categories
                if (account.type === 'Income') {
                    category = 'Sales Revenue';
                } else if (account.type === 'Expense') {
                    category = account.name; // Use account name as category
                } else if (account.type === 'Asset' || account.type === 'Liability') {
                    // Could be more specific based on context
                    category = account.name.includes('Bank') || account.name.includes('Cash') ? 'Bank/Cash' : account.name;
                } else {
                    category = account.name;
                }
            }
        }

        transactionsToInsert.push({
          user_id: userId,
          type: transactionType,
          amount: amtAbs,
          description: r.description ?? 'Imported',
          date: r.txn_date,
          category: category,
          account_id: primaryAccountId ? Number(primaryAccountId) : null, // Ensure it's a number or null
          original_text: r.description ?? 'Imported',
          source: `import-batch-${batchId}`, // Indicate source
          confirmed: true // Mark as confirmed upon import
        });
        // --- END NEW ---

        posted++;
        continue;
      }

      // CASE B: Need to determine one side → use Cash/Bank + guess for the non-bank leg
      const isCash = !!r.proposed_cash; // NEW flag
      const bankLabel = isCash ? "Cash" : "Bank Account";

      const bankSideId = await findAccountId(cx, userId, bankLabel);
      if (!bankSideId) {
        skipped++;
        await cx.query(`UPDATE public.import_rows SET error=$1 WHERE id=$2`, [`Missing ${bankLabel} account`, r.id]);
        continue;
      }

      // Guess the counter-leg (non-bank) if not given by user
      let nonbankId: number | null = null;
      const guess = guessAccounts(r.description || "", Number(r.amount));

      if (isInflow) {
        // Inflow → Dr bank/cash, Cr non-bank (revenue/etc)
        nonbankId = r.proposed_credit_account_id
          ?? (await findAccountId(cx, userId, guess.credit));
      } else {
        // Outflow → Dr non-bank (expense/etc), Cr bank/cash
        nonbankId = r.proposed_debit_account_id
          ?? (await findAccountId(cx, userId, guess.debit));
      }

      if (!nonbankId) {
        skipped++;
        await cx.query(`UPDATE public.import_rows SET error=$1 WHERE id=$2`, ["Missing mapped accounts", r.id]);
        continue;
      }

      // Create the entry
      const je = await cx.query(
        `INSERT INTO public.journal_entries (entry_date, memo, user_id)
           VALUES ($1,$2,$3) RETURNING id`,
        [r.txn_date, r.description ?? 'Imported', userId]
      );
      const entryId = je.rows[0].id;

      const lines: Array<{ entryId:number; accountId:number; debit:number; credit:number }> = [];
      if (isInflow) {
        // Dr Cash/Bank, Cr non-bank
        lines.push({ entryId, accountId: bankSideId, debit: amtAbs, credit: 0 });
        lines.push({ entryId, accountId: nonbankId,  debit: 0,      credit: amtAbs });
      } else {
        // Dr non-bank, Cr Cash/Bank
        lines.push({ entryId, accountId: nonbankId,  debit: amtAbs, credit: 0 });
        lines.push({ entryId, accountId: bankSideId, debit: 0,      credit: amtAbs });
      }

      // Optional VAT line (unchanged)
      if (r.proposed_vat_account_id && Number(r.proposed_vat_amount || 0) !== 0) {
        const vatAmt = Number(r.proposed_vat_amount);
        lines.push({
          entryId,
          accountId: r.proposed_vat_account_id,
          debit:  vatAmt > 0 ? vatAmt : 0,
          credit: vatAmt < 0 ? -vatAmt : 0,
        });
      }

      // bulk insert lines
      const values: string[] = [];
      const params: any[] = [];
      let i = 1;
      for (const l of lines) {
        values.push(`($${i++}, $${i++}, $${i++}, $${i++}, $${i++})`);
        params.push(l.entryId, l.accountId, userId, l.debit, l.credit);
      }
      await cx.query(
        `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
         VALUES ${values.join(",")}`,
        params
      );

      // --- NEW: Prepare transaction data for insertion (for Case B) ---
      // Determine primary account and type for transactions table
      const primaryAccountIdCaseB = isInflow ? nonbankId : nonbankId; // In both sub-cases, nonbankId is the primary account for the transaction record
      const transactionTypeCaseB: 'income' | 'expense' = isInflow ? 'income' : 'expense';
      
      // Determine category (this can be refined)
      let categoryCaseB = 'Imported'; // Default category
      if (primaryAccountIdCaseB) {
          // Fetch account name/type to determine a better category
          const accountRes = await cx.query('SELECT name, type FROM public.accounts WHERE id = $1 AND user_id = $2', [primaryAccountIdCaseB, userId]);
          if (accountRes.rows.length > 0) {
              const account = accountRes.rows[0];
              // Map account types/names to transaction categories
              if (account.type === 'Income') {
                  categoryCaseB = 'Sales Revenue';
              } else if (account.type === 'Expense') {
                  categoryCaseB = account.name; // Use account name as category
              } else if (account.type === 'Asset' || account.type === 'Liability') {
                  // Could be more specific based on context
                  categoryCaseB = account.name.includes('Bank') || account.name.includes('Cash') ? 'Bank/Cash' : account.name;
              } else {
                  categoryCaseB = account.name;
              }
          }
      }

      transactionsToInsert.push({
        user_id: userId,
        type: transactionTypeCaseB,
        amount: amtAbs,
        description: r.description ?? 'Imported',
        date: r.txn_date,
        category: categoryCaseB,
        account_id: primaryAccountIdCaseB ? Number(primaryAccountIdCaseB) : null, // Ensure it's a number or null
        original_text: r.description ?? 'Imported',
        source: `import-batch-${batchId}`, // Indicate source
        confirmed: true // Mark as confirmed upon import
      });
      // --- END NEW ---

      posted++;
    }

    // --- NEW: Bulk Insert into transactions table ---
    if (transactionsToInsert.length > 0) {
        const transactionInsertQuery = `
            INSERT INTO public.transactions 
            (user_id, type, amount, description, date, category, account_id, original_text, source, confirmed)
            VALUES 
            ${transactionsToInsert.map((_, i) => `($${i * 10 + 1}, $${i * 10 + 2}, $${i * 10 + 3}, $${i * 10 + 4}, $${i * 10 + 5}, $${i * 10 + 6}, $${i * 10 + 7}, $${i * 10 + 8}, $${i * 10 + 9}, $${i * 10 + 10})`).join(', ')}
        `;
        
        // Flatten the array of objects into a single array of values
        const transactionValues = transactionsToInsert.flatMap(tx => [
            tx.user_id, tx.type, tx.amount, tx.description, tx.date, 
            tx.category, tx.account_id, tx.original_text, tx.source, tx.confirmed
        ]);

        await cx.query(transactionInsertQuery, transactionValues);
        console.log(`[IMPORT] Inserted ${transactionsToInsert.length} records into public.transactions`);
    }
    // --- END NEW ---

    await cx.query(
      `UPDATE public.import_batches
          SET status='committed', committed_at=now()
        WHERE id=$1`,
      [batchId]
    );

    await cx.query("COMMIT");
    res.json({ 
        batchId, 
        posted, 
        skipped,
        transactions_recorded: transactionsToInsert.length // Report back how many were recorded
    });
  } catch (e: any) {
    await cx.query("ROLLBACK");
    console.error('[IMPORT] Error committing batch:', e); // Log the full error
    res.status(500).json({ 
        error: "Failed to commit import batch", 
        detail: e?.message || String(e) 
    });
  } finally {
    cx.release();
  }
});


// Save user overrides onto import_rows
// Save user overrides onto import_rows
// PATCH /imports/rows/:rowId  → update proposed account mapping
app.patch("/imports/rows/:rowId", authMiddleware, async (req, res) => {
  const userId = req.user!.parent_user_id;
  const rowId = Number(req.params.rowId);
  const {
    proposed_debit_account_id,
    proposed_credit_account_id,
    proposed_cash, // NEW
  } = req.body || {};

  if (!rowId) return res.status(400).json({ error: "rowId required" });
  if (
    proposed_debit_account_id == null &&
    proposed_credit_account_id == null &&
    typeof proposed_cash !== "boolean"
  ) {
    return res.status(400).json({ error: "nothing to update" });
  }

  const cx = await pool.connect();
  try {
    await cx.query("BEGIN");

    const parts: string[] = [];
    const vals: any[] = [rowId, userId];

    if (proposed_debit_account_id != null) {
      parts.push(`proposed_debit_account_id = $${vals.length + 1}`);
      vals.push(Number(proposed_debit_account_id));
    }
    if (proposed_credit_account_id != null) {
      parts.push(`proposed_credit_account_id = $${vals.length + 1}`);
      vals.push(Number(proposed_credit_account_id));
    }
    if (typeof proposed_cash === "boolean") {
      parts.push(`proposed_cash = $${vals.length + 1}`);
      vals.push(proposed_cash);
    }

    await cx.query(
      `UPDATE public.import_rows
         SET ${parts.join(", ")}
       WHERE id = $1 AND user_id = $2`,
      vals
    );

    await cx.query("COMMIT");
    res.json({ ok: true });
  } catch (e:any) {
    await cx.query("ROLLBACK");
    res.status(400).json({ error: e?.message || String(e) });
  } finally {
    cx.release();
  }
});

// --- helper: ensure Opening Balance Equity exists for this user
async function ensureOBEAccount(cx: any, userId: string | number) {
  const q = await cx.query(
    `SELECT id FROM public.accounts 
      WHERE user_id=$1 AND lower(name)=lower('Opening Balance Equity') LIMIT 1`,
    [userId]
  );
  if (q.rows.length) return q.rows[0].id;

  // Choose a code that's unlikely to clash; adjust if you have a code generator
  const ins = await cx.query(
    `INSERT INTO public.accounts (user_id, code, name, type, normal_side, is_active)
     VALUES ($1,$2,$3,$4,$5,true)
     RETURNING id`,
    [userId, '3999', 'Opening Balance Equity', 'Equity', 'Credit']
  );
  return ins.rows[0].id;
}

// --- helper: load minimal account info (and validate ownership)
async function loadAccountsMap(cx: any, userId: string | number, accountIds: number[]) {
  if (!accountIds.length) return new Map<number, any>();
  const { rows } = await cx.query(
    `SELECT id, name, type, COALESCE(normal_side,
       CASE WHEN type IN ('Asset','Expense') THEN 'Debit' ELSE 'Credit' END
     ) AS normal_side
     FROM public.accounts
     WHERE user_id=$1 AND id = ANY($2::int[])`,
    [userId, accountIds]
  );
  const map = new Map<number, any>();
  for (const r of rows) map.set(Number(r.id), r);
  return map;
}

/**
 * POST /setup/opening-balance
 * Body:
 * {
 *   "asOf": "2025-01-01",
 *   "balances": [
 *     { "account_id": 1000, "amount": 2000 },   // amount is on the account's normal side
 *     { "account_id": 1010, "amount": 500000 }, // e.g., Asset (Debit-normal) -> Dr 500,000
 *     { "account_id": 2100, "amount": 12000 }   // e.g., Liability (Credit-normal) -> Cr 12,000
 *   ]
 * }
 */
app.post("/setup/opening-balance", authMiddleware, async (req, res) => {
  const userId = req.user!.parent_user_id;
  const { asOf, balances } = req.body || {};

  if (!asOf) return res.status(400).json({ error: "asOf required (YYYY-MM-DD)" });
  if (!Array.isArray(balances) || balances.length === 0) {
    return res.status(400).json({ error: "balances[] required" });
  }

  const cx = await pool.connect();
  try {
    await cx.query("BEGIN");

    const obeId = await ensureOBEAccount(cx, userId);

    // Validate accounts belong to user
    const ids = balances.map((b: any) => Number(b.account_id)).filter(Boolean);
    const acctMap = await loadAccountsMap(cx, userId, ids);
    if (acctMap.size !== ids.length) {
      throw new Error("One or more accounts not found or not owned by user");
    }

    // If there is an older Opening JE for this date, remove it (idempotent)
    const prior = await cx.query(
      `SELECT id FROM public.journal_entries 
         WHERE user_id=$1 AND entry_date=$2::date AND memo='Opening Balances'`,
      [userId, asOf]
    );
    for (const p of prior.rows) {
      await cx.query(`DELETE FROM public.journal_lines WHERE user_id=$1 AND entry_id=$2`, [userId, p.id]);
      await cx.query(`DELETE FROM public.journal_entries WHERE user_id=$1 AND id=$2`, [userId, p.id]);
    }

    // Create new JE
    const je = await cx.query(
      `INSERT INTO public.journal_entries (entry_date, memo, user_id)
       VALUES ($1, 'Opening Balances', $2) RETURNING id`,
      [asOf, userId]
    );
    const entryId = je.rows[0].id;

    // Build lines from "normal-side amounts"
    // Rule:
    // - If account.normal_side='Debit'  and amount>0  => Dr amount
    // - If account.normal_side='Debit'  and amount<0  => Cr -amount
    // - If account.normal_side='Credit' and amount>0  => Cr amount
    // - If account.normal_side='Credit' and amount<0  => Dr -amount
    type Line = { entryId:number; accountId:number; debit:number; credit:number; };
    const lines: Line[] = [];
    let totalDr = 0, totalCr = 0;

    for (const b of balances) {
      const accountId = Number(b.account_id);
      const amt = Number(b.amount || 0);
      if (!accountId || !Number.isFinite(amt)) continue;

      const acc = acctMap.get(accountId);
      let debit = 0, credit = 0;

      if (acc.normal_side === 'Debit') {
        if (amt >= 0) debit = amt; else credit = -amt;
      } else { // Credit-normal
        if (amt >= 0) credit = amt; else debit = -amt;
      }

      if (debit === 0 && credit === 0) continue;

      lines.push({ entryId, accountId, debit, credit });
      totalDr += debit; totalCr += credit;
    }

    // Plug to Opening Balance Equity so the entry balances
    const diff = totalDr - totalCr;
    if (Math.abs(diff) > 0.0001) {
      // If Dr > Cr, plug a Credit; if Cr > Dr, plug a Debit
      const plug: Line = {
        entryId,
        accountId: Number(obeId),
        debit: diff < 0 ? -diff : 0,
        credit: diff > 0 ?  diff : 0
      };
      lines.push(plug);
    }

    // Insert lines
    if (!lines.length) throw new Error("No non-zero opening amounts to post");
    const values: string[] = [];
    const params: any[] = [];
    let i = 1;
    for (const l of lines) {
      values.push(`($${i++}, $${i++}, $${i++}, $${i++}, $${i++})`);
      params.push(l.entryId, l.accountId, userId, l.debit, l.credit);
    }
    await cx.query(
      `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
       VALUES ${values.join(",")}`, params
    );

    await cx.query("COMMIT");
    res.json({ ok: true, entryId, lines: lines.length });
  } catch (e:any) {
    await cx.query("ROLLBACK");
    res.status(400).json({ error: e?.message || String(e) });
  } finally {
    cx.release();
  }
});

// Optional: fetch what’s been set (summarized)
app.get("/setup/opening-balance", authMiddleware, async (req, res) => {
  const userId = req.user!.parent_user_id;
  const asOf = req.query.asOf as string;
  if (!asOf) return res.status(400).json({ error: "asOf required" });

  const { rows } = await pool.query(
    `SELECT a.id as account_id, a.name, a.type,
            SUM(jl.debit) AS debit, SUM(jl.credit) AS credit
       FROM public.journal_entries je
       JOIN public.journal_lines jl ON jl.entry_id=je.id AND jl.user_id=je.user_id
       JOIN public.accounts a      ON a.id=jl.account_id AND a.user_id=jl.user_id
      WHERE je.user_id=$1 AND je.entry_date=$2::date AND je.memo='Opening Balances'
      GROUP BY a.id, a.name, a.type
      ORDER BY a.type, a.name`,
    [userId, asOf]
  );
  res.json({ asOf, lines: rows });
});



// server.ts

// --- ENDPOINT: Daily Sales Aggregation (For Calendar Heatmap) ---
// Uses public.sales table

// --- END ENDPOINT ---
// server.ts

// --- ENDPOINT: Monthly Expenses by Category (For Bar Race) ---
// Uses public.journal_lines, public.accounts, public.reporting_categories, public.journal_entries
// --- NEW ENDPOINT: Monthly Expenses by Category (For Bar Race) ---
app.get('/api/charts/monthly-expenses', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    console.log("[DEBUG] /api/charts/monthly-expenses called for user:", user_id);

    try {
        // Query to get monthly totals for each expense category
        const dataResult = await pool.query(
            `
            SELECT 
                DATE_TRUNC('month', t.date)::date AS month,
                COALESCE(t.category, 'Uncategorized') AS category,
                SUM(t.amount) AS amount
            FROM public.transactions t
            WHERE t.user_id = $1
              AND t.type = 'expense'
            GROUP BY DATE_TRUNC('month', t.date), t.category
            ORDER BY month, category
            `,
            [user_id]
        );
        
        console.log("[DEBUG] Query returned", dataResult.rowCount, "rows");
        console.log("[DEBUG] Raw query results:", JSON.stringify(dataResult.rows));

        // Format data into an array of objects with month and values for each category
        const rawData = dataResult.rows;
        const monthlyDataMap: Record<string, Record<string, number>> = {};
        const monthsSet = new Set<string>();
        const categoriesSet = new Set<string>();

        rawData.forEach(row => {
            // Format month as 'YYYY-MM-DD' (first day of the month)
            const monthStr = new Date(row.month).toISOString().split('T')[0]; 
            monthsSet.add(monthStr);
            categoriesSet.add(row.category);

            if (!monthlyDataMap[monthStr]) {
                monthlyDataMap[monthStr] = {};
            }
            // Ensure amount is a number
            monthlyDataMap[monthStr][row.category] = parseFloat(row.amount) || 0;
        });

        // Sort months chronologically
        const sortedMonths = Array.from(monthsSet).sort();

        // Create final array, ensuring all categories have a value (0 if no data) for each month
        const finalData = sortedMonths.map(month => {
            const monthData: any = { month }; 
            categoriesSet.forEach(cat => {
                monthData[cat] = monthlyDataMap[month][cat] || 0;
            });
            return monthData;
        });

        console.log("[DEBUG] Sending response with", finalData.length, "data points");
        res.json(finalData);
    } catch (error) {
        console.error('[ERROR] Error fetching monthly expenses for bar race:', error);
        res.status(500).json({ error: 'Failed to fetch monthly expense data for bar race' });
    }
});
// --- END ENDPOINT ---
// server.ts (This one is likely already correct based on your file)

// --- ENDPOINT: Top Selling Products ---
// Uses public.sale_items and public.sales
app.get('/api/charts/top-selling-products', authMiddleware, async (req, res) => {
  const user_id = req.user!.parent_user_id;
  try {
    // Query using sale_items.quantity and joining with sales for user_id
    const result = await pool.query(
      `
      SELECT 
        si.product_name,
        SUM(si.quantity) AS total_quantity_sold
      FROM public.sale_items si
      JOIN public.sales s ON si.sale_id = s.id
      WHERE s.user_id = $1
      GROUP BY si.product_name
      ORDER BY total_quantity_sold DESC
      LIMIT 5;
      `,
      [user_id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching top-selling products:', error);
    res.status(500).json({ error: 'Failed to fetch top-selling products' });
  }
});
// --- END ENDPOINT ---

// server.ts

// ... other imports and code ...

// --- NEW ENDPOINT: Daily Sales Aggregation (For Calendar Heatmap) ---

app.get('/api/charts/daily-sales-aggregation', authMiddleware, async (req: Request, res: Response) => {
  console.log("[DEBUG] /api/charts/daily-sales-aggregation called");
  
  if (!req.user) {
    console.error("[ERROR] req.user is undefined in /api/charts/daily-sales-aggregation");
    return res.status(401).json({ error: 'Unauthorized: User information missing.' });
  }

  const user_id = req.user.parent_user_id;
  console.log(`[DEBUG] User ID for query: ${user_id}`);

  if (!user_id) {
    console.error("[ERROR] parent_user_id is undefined for user:", req.user);
    return res.status(400).json({ error: 'User ID not found.' });
  }

  try {
    console.log(`[DEBUG] Executing query for user_id: ${user_id}`);
    const result = await pool.query(
      `
      SELECT 
        DATE(s.created_at) AS date,
        SUM(s.total_amount) AS total_sales_amount
      FROM public.sales s
      WHERE s.user_id = $1
      GROUP BY DATE(s.created_at)
      ORDER BY date;
      `,
      [user_id]
    );
   // console.log(`[DEBUG] Query returned ${result.rows.length} rows`);
    
    // Log the actual data returned by the query
    //console.log("[DEBUG] Raw query results:", JSON.stringify(result.rows));

const formattedData = result.rows.map(row => ({
  // Explicitly format the date as YYYY-MM-DD string
  date: row.date instanceof Date ? row.date.toISOString().split('T')[0] : 
        typeof row.date === 'string' ? row.date.split('T')[0] : 
        new Date(row.date).toISOString().split('T')[0],
  total_sales_amount: parseFloat(row.total_sales_amount) || 0
}));

   //console.log(`[DEBUG] Sending response with ${formattedData.length} data points`);
   // console.log("[DEBUG] Formatted data:", JSON.stringify(formattedData));
    res.json(formattedData);
  } catch (error) {
    console.error('[ERROR] Error fetching daily sales aggregation:', error);
    res.status(500).json({ error: 'Failed to fetch daily sales data for heatmap' });
  }
});
// --- END NEW ENDPOINT ---
// --- END NEW ENDPOINT ---

// server.ts

// --- NEW ENDPOINT: Get Products with Cluster Data ---
// This endpoint fetches products and enriches them with sales data for clustering
app.get('/api/products/cluster-data', authMiddleware, async (req: Request, res: Response) => {
  const userId = req.user!.parent_user_id;

  try {
    // Join products with sales_items to get sales counts and totals
    // Also join with the new transactions table to get purchase data
    const { rows } = await pool.query(
      `
      SELECT 
        p.id,
        p.name,
        p.description,
        p.unit_price AS price,
        p.cost_price,
        p.sku,
        p.is_service,
        p.stock_quantity AS stock,
        p.vat_rate,
        p.category,
        p.unit,
        p.user_id,
        -- Aggregated Sales Data
        COALESCE(SUM(si.quantity), 0) AS total_sold,
        COUNT(si.id) AS number_of_sales, -- Number of sale items, not distinct sales
        COALESCE(SUM(si.subtotal), 0) AS total_revenue,
        -- Aggregated Purchase Data (from transactions)
        COALESCE(SUM(CASE WHEN t.type = 'expense' AND t.description ILIKE '%' || p.name || '%' THEN t.amount ELSE 0 END), 0) AS total_purchased_cost,
        COALESCE(SUM(CASE WHEN t.type = 'expense' AND t.description ILIKE '%' || p.name || '%' THEN 1 ELSE 0 END), 0) AS number_of_purchases
      FROM public.products_services p
      LEFT JOIN public.sale_items si ON p.id = si.product_id AND p.user_id = si.user_id
      LEFT JOIN public.transactions t ON p.user_id = t.user_id 
        AND t.type = 'expense' 
        AND (t.description ILIKE '%' || p.name || '%' OR t.original_text ILIKE '%' || p.name || '%')
      WHERE p.user_id = $1
      GROUP BY p.id, p.name, p.description, p.unit_price, p.cost_price, p.sku, p.is_service, 
               p.stock_quantity, p.vat_rate, p.category, p.unit, p.user_id
      ORDER BY p.name
      `,
      [userId]
    );

    // Map the database columns to the frontend Product interface and add derived metrics
    const productsWithMetrics = rows.map((row: any) => ({
      id: row.id.toString(),
      name: row.name,
      description: row.description,
      price: parseFloat(row.price) || 0,
      costPrice: parseFloat(row.cost_price) || null,
      sku: row.sku,
      isService: row.is_service,
      stock: parseInt(row.stock, 10) || 0,
      vatRate: parseFloat(row.vat_rate) || 0,
      category: row.category,
      unit: row.unit,
      // Derived metrics for clustering
      totalSold: parseInt(row.total_sold, 10) || 0,
      numberOfSales: parseInt(row.number_of_sales, 10) || 0,
      totalRevenue: parseFloat(row.total_revenue) || 0,
      totalPurchasedCost: parseFloat(row.total_purchased_cost) || 0,
      numberOfPurchases: parseInt(row.number_of_purchases, 10) || 0,
      // Calculated metrics
      averageSellingPrice: row.total_sold > 0 ? parseFloat(row.total_revenue) / parseInt(row.total_sold, 10) : parseFloat(row.price) || 0,
      grossProfit: (parseFloat(row.total_revenue) || 0) - (parseFloat(row.total_purchased_cost) || 0),
      stockStatus: parseInt(row.stock, 10) || 0 // Will derive textual status in frontend
    }));

    res.json(productsWithMetrics);
  } catch (err) {
    console.error('[PRODUCTS CLUSTER] Error fetching products with cluster data:', err);
    res.status(500).json({ error: 'Failed to fetch products with cluster data.' });
  }
});

// server.ts

// --- NEW ENDPOINT: Migrate Transactions to Journal Entries ---
app.post('/api/migrate-transactions-to-journal', authMiddleware, async (req: Request, res: Response) => {
  console.log("[MIGRATION] Starting migration of transactions to journal entries...");
  
  const userId = req.user!.parent_user_id;
  if (!userId) {
    console.error("[MIGRATION ERROR] User ID not found.");
    return res.status(400).json({ error: 'User ID not found.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Fetch unmigrated transactions for the user
    console.log(`[MIGRATION] Fetching unmigrated transactions for user ${userId}...`);
    const transactionsRes = await client.query(
      `SELECT id, "type", amount, description, "date", category, account_id, original_text, "source", confirmed, user_id, migrated_to_journal
       FROM public.transactions
       WHERE user_id = $1 AND (migrated_to_journal IS NULL OR migrated_to_journal = FALSE)
       ORDER BY "date", id`,
      [userId]
    );
    const transactions = transactionsRes.rows;
    console.log(`[MIGRATION] Found ${transactions.length} transactions to migrate.`);

    if (transactions.length === 0) {
      await client.query('COMMIT');
      console.log("[MIGRATION] No transactions to migrate.");
      return res.status(200).json({ message: 'No transactions to migrate.', migrated: 0 });
    }

    // 2. Find the default Cash/Bank account for the user (you might have a specific way to identify this)
    console.log(`[MIGRATION] Finding default Cash/Bank account for user ${userId}...`);
    const cashAccountRes = await client.query(
      `SELECT id FROM public.accounts 
       WHERE user_id = $1 AND (name ILIKE '%cash%' OR name ILIKE '%bank%') AND is_active = TRUE AND is_postable = TRUE
       ORDER BY id LIMIT 1`, // Simple logic: pick the first Cash/Bank account found
      [userId]
    );
    const cashAccountId = cashAccountRes.rows[0]?.id;
    if (!cashAccountId) {
      await client.query('ROLLBACK');
      console.error("[MIGRATION ERROR] No default Cash/Bank account found for user.", userId);
      return res.status(400).json({ error: 'No default Cash/Bank account found for user. Please create one before migrating.' });
    }
    console.log(`[MIGRATION] Using Cash/Bank account ID: ${cashAccountId}`);

    let migratedCount = 0;
    const errors: string[] = [];

    // 3. Process each transaction
    console.log(`[MIGRATION] Starting to process ${transactions.length} transactions...`);
    for (const tx of transactions) {
      try {
        const txId = tx.id;
        const txType = tx.type; // 'income', 'expense', 'transfer', 'adjustment'
        const txAmount = parseFloat(tx.amount) || 0;
        const txDescription = tx.description || tx.original_text || 'Migrated Transaction';
        const txDate = tx.date; // 'YYYY-MM-DD'
        const txAccountId = tx.account_id; // Primary account
        
        console.log(`[MIGRATION] Processing transaction ID ${txId} (${txType}, R${txAmount})...`);

        // Skip if amount is zero or no primary account
        if (txAmount === 0) {
          console.warn(`[MIGRATION WARN] Skipping transaction ID ${txId}: Amount is zero.`);
          errors.push(`Transaction ID ${txId}: Skipped (Amount is zero)`);
          continue;
        }
        if (!txAccountId) {
          console.warn(`[MIGRATION WARN] Skipping transaction ID ${txId}: No primary account_id.`);
          errors.push(`Transaction ID ${txId}: Skipped (No primary account)`);
          continue;
        }

        // 4. Determine Debit and Credit accounts and amounts
        let debitAccountId: number | null = null;
        let creditAccountId: number | null = null;
        let debitAmount: number = 0;
        let creditAmount: number = Math.abs(txAmount); // Use absolute value

        if (txType === 'income') {
          // Income: Dr Cash/Bank, Cr Revenue (Primary Account)
          debitAccountId = cashAccountId;
          creditAccountId = txAccountId;
          debitAmount = creditAmount; // Both sides equal for balanced entry
        } else if (txType === 'expense') {
          // Expense: Dr Expense (Primary Account), Cr Cash/Bank
          debitAccountId = txAccountId;
          creditAccountId = cashAccountId;
          debitAmount = creditAmount; // Both sides equal for balanced entry
        } else {
          // For 'transfer' or 'adjustment', we might skip or need special logic
          // Let's skip them for now and log a warning
          console.warn(`[MIGRATION WARN] Skipping transaction ID ${txId}: Type '${txType}' not supported for automatic migration.`);
          errors.push(`Transaction ID ${txId}: Skipped (Type '${txType}' not supported)`);
          continue;
        }

        // 5. Create Journal Entry
        const jeRes = await client.query(
          `INSERT INTO public.journal_entries (entry_date, memo, user_id, source)
           VALUES ($1, $2, $3, $4)
           RETURNING id`,
          [txDate, txDescription, userId, `migration-${tx.source || 'manual'}`]
        );
        const journalEntryId = jeRes.rows[0].id;
        console.log(`[MIGRATION] Created Journal Entry ID ${journalEntryId} for transaction ${txId}.`);

        // 6. Create Journal Lines
        const lines: Array<{ entryId: number; accountId: number; debit: number; credit: number }> = [];
        if (debitAccountId) {
          lines.push({ entryId: journalEntryId, accountId: debitAccountId, debit: debitAmount, credit: 0 });
        }
        if (creditAccountId) {
          lines.push({ entryId: journalEntryId, accountId: creditAccountId, debit: 0, credit: creditAmount });
        }

        if (lines.length !== 2) {
            throw new Error(`Failed to create 2 lines for journal entry ${journalEntryId}. Only created ${lines.length}.`);
        }

        // Bulk insert lines
        const lineValues: string[] = [];
        const lineParams: any[] = [];
        let paramIndex = 1;
        for (const l of lines) {
          lineValues.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
          lineParams.push(l.entryId, l.accountId, userId, l.debit, l.credit);
        }
        await client.query(
          `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
           VALUES ${lineValues.join(", ")}`,
          lineParams
        );
        console.log(`[MIGRATION] Created ${lines.length} Journal Lines for entry ${journalEntryId}.`);

        // 7. Mark transaction as migrated
        await client.query(
          `UPDATE public.transactions SET migrated_to_journal = TRUE WHERE id = $1 AND user_id = $2`,
          [txId, userId]
        );
        console.log(`[MIGRATION] Marked transaction ID ${txId} as migrated.`);

        migratedCount++;

      } catch (txError: any) {
        console.error(`[MIGRATION ERROR] Failed to migrate transaction ID ${tx.id}:`, txError);
        errors.push(`Transaction ID ${tx.id}: Failed (${txError.message})`);
        // Decide whether to continue with other transactions or rollback everything
        // For now, let's continue to migrate as many as possible
        // await client.query('ROLLBACK'); // Uncomment if you want to stop on first error
        // return res.status(500).json({ error: `Migration failed for transaction ID ${tx.id}`, detail: txError.message });
      }
    }

    await client.query('COMMIT');
    console.log(`[MIGRATION] Migration completed. Migrated ${migratedCount} transactions.`);
    res.json({ 
      message: `Migration completed. Migrated ${migratedCount} transactions.`, 
      migrated: migratedCount,
      errors: errors.length > 0 ? errors : undefined
    });

  } catch (error: any) {
    await client.query('ROLLBACK');
    console.error('[MIGRATION ERROR] Migration failed:', error);
    res.status(500).json({ error: 'Migration failed', detail: error.message });
  } finally {
    client.release();
  }
});
// --- END NEW ENDPOINT ---


// Example SQL for Revenue Endpoint (GET /api/stats/revenue?startDate=...&endDate=...)
// Replace the entire /api/stats/revenue endpoint with this version
app.get("/api/stats/revenue", authMiddleware, async (req, res) => {
    const userId = req.user!.parent_user_id;
    const startDate = req.query.startDate as string | undefined;
    const endDate = req.query.endDate as string | undefined;

    try {
        // --- Current Period Revenue ---
        let currentQuery = `
            SELECT COALESCE(SUM(jl.credit), 0)::numeric(14, 2) AS total_revenue
            FROM public.journal_lines jl
            JOIN public.journal_entries je ON jl.entry_id = je.id AND jl.user_id = je.user_id
            JOIN public.accounts a ON jl.account_id = a.id AND jl.user_id = a.user_id
            JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
            WHERE je.user_id = $1
              AND rc.statement = 'income_statement'
              AND rc.section = 'revenue' -- Changed from a.type = 'Income'
              AND je.entry_date >= $2
              AND je.entry_date <= $3
        `;
        let currentParams: any[] = [userId, '1970-01-01', '9999-12-31']; // Default wide range
        if (startDate) currentParams[1] = startDate;
        if (endDate) currentParams[2] = endDate;

        const currentResult = await pool.query(currentQuery, currentParams);
        const currentRevenue = parseFloat(currentResult.rows[0]?.total_revenue) || 0;

        // --- Previous Period Revenue (for comparison) ---
        let previousQuery = `
            SELECT COALESCE(SUM(jl.credit), 0)::numeric(14, 2) AS total_revenue
            FROM public.journal_lines jl
            JOIN public.journal_entries je ON jl.entry_id = je.id AND jl.user_id = je.user_id
            JOIN public.accounts a ON jl.account_id = a.id AND jl.user_id = a.user_id
            JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
            WHERE je.user_id = $1
              AND rc.statement = 'income_statement'
              AND rc.section = 'revenue' -- Changed from a.type = 'Income'
              AND je.entry_date >= $2
              AND je.entry_date < $3 -- Use < start to get previous period
        `;
        let previousParams: any[] = [userId, '1970-01-01', currentParams[1]]; // Default, previous period ends before current starts

        // Calculate a simple previous period (e.g., same number of days before the current period)
        if (startDate && endDate) {
             const start = new Date(startDate);
             const end = new Date(endDate);
             const diffTime = Math.abs(end.getTime() - start.getTime());
             const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1; // +1 to make it inclusive like the main period?

             const previousEnd = new Date(start.getTime() - 1000 * 60 * 60 * 24); // One day before start
             const previousStart = new Date(previousEnd.getTime() - diffTime); // Same duration before that

             previousParams = [userId, previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]];
        } else if (startDate) {
            // If only start date, maybe compare to a fixed duration before?
            const start = new Date(startDate);
            const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
            const previousEnd = new Date(start.getTime() - 1000 * 60 * 60 * 24); // One day before
            const previousStart = new Date(previousEnd.getTime() - thirtyDaysMs);
            previousParams = [userId, previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]];
        }

        const previousResult = await pool.query(previousQuery, previousParams);
        const previousRevenue = parseFloat(previousResult.rows[0]?.total_revenue) || 0;

        // --- Calculate Change ---
        let changePercentage = 0;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';
        if (previousRevenue !== 0) {
            changePercentage = ((currentRevenue - previousRevenue) / Math.abs(previousRevenue)) * 100;
            changeType = changePercentage > 0 ? 'increase' : changePercentage < 0 ? 'decrease' : 'neutral';
        } else if (currentRevenue > 0) {
             changeType = 'increase'; // Went from 0 to positive
        } else if (currentRevenue < 0) {
             changeType = 'decrease'; // Went from 0 to negative (unlikely for revenue, but possible in accounting)
        }

        res.json({
            value: currentRevenue,
            previousValue: previousRevenue,
            changePercentage: parseFloat(changePercentage.toFixed(2)),
            changeType: changeType
        });

    } catch (err: any) {
        console.error("Error fetching revenue stats:", err);
        res.status(500).json({ error: "Failed to fetch revenue statistics.", detail: err.message });
    }
});


app.get("/api/stats/expenses", authMiddleware, async (req, res) => {
    const userId = req.user!.parent_user_id;
    const startDate = req.query.startDate as string | undefined;
    const endDate = req.query.endDate as string | undefined;

    try {
        // --- Current Period Expenses ---
        let currentQuery = `
            SELECT COALESCE(SUM(jl.debit), 0)::numeric(14, 2) AS total_expenses
            FROM public.journal_lines jl
            JOIN public.journal_entries je ON jl.entry_id = je.id AND jl.user_id = je.user_id
            JOIN public.accounts a ON jl.account_id = a.id AND jl.user_id = a.user_id
            JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
            WHERE je.user_id = $1
              AND rc.statement = 'income_statement'
              AND rc.section IN ('operating_expenses') -- Include ALL expense sections
              AND je.entry_date >= $2
              AND je.entry_date <= $3
        `;
        let currentParams: any[] = [userId, '1970-01-01', '9999-12-31'];
        if (startDate) currentParams[1] = startDate;
        if (endDate) currentParams[2] = endDate;

        const currentResult = await pool.query(currentQuery, currentParams);
        const currentExpenses = parseFloat(currentResult.rows[0]?.total_expenses) || 0;

         // --- Previous Period Expenses (for comparison) ---
        let previousQuery = `
            SELECT COALESCE(SUM(jl.debit), 0)::numeric(14, 2) AS total_expenses
            FROM public.journal_lines jl
            JOIN public.journal_entries je ON jl.entry_id = je.id AND jl.user_id = je.user_id
            JOIN public.accounts a ON jl.account_id = a.id AND jl.user_id = a.user_id
            JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id
            WHERE je.user_id = $1
              AND rc.statement = 'income_statement'
              AND rc.section IN ('operating_expenses')
              AND je.entry_date >= $2
              AND je.entry_date < $3
        `;
        // Calculate previous period dates (same logic as revenue)
        let previousParams: any[] = [userId, '1970-01-01', currentParams[1]];

        if (startDate && endDate) {
             const start = new Date(startDate);
             const end = new Date(endDate);
             const diffTime = Math.abs(end.getTime() - start.getTime());
             const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;

             const previousEnd = new Date(start.getTime() - 1000 * 60 * 60 * 24);
             const previousStart = new Date(previousEnd.getTime() - diffTime);

             previousParams = [userId, previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]];
        } else if (startDate) {
            const start = new Date(startDate);
            const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
            const previousEnd = new Date(start.getTime() - 1000 * 60 * 60 * 24);
            const previousStart = new Date(previousEnd.getTime() - thirtyDaysMs);
            previousParams = [userId, previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]];
        }

        const previousResult = await pool.query(previousQuery, previousParams);
        const previousExpenses = parseFloat(previousResult.rows[0]?.total_expenses) || 0;

        // --- Calculate Change ---
        let changePercentage = 0;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';
        if (previousExpenses !== 0) {
            changePercentage = ((currentExpenses - previousExpenses) / Math.abs(previousExpenses)) * 100;
            changeType = changePercentage > 0 ? 'increase' : changePercentage < 0 ? 'decrease' : 'neutral';
        } else if (currentExpenses > 0) {
             changeType = 'increase';
        } else if (currentExpenses < 0) {
             changeType = 'decrease'; // Unlikely for expenses
        }

        res.json({
            value: currentExpenses,
            previousValue: previousExpenses,
            changePercentage: parseFloat(changePercentage.toFixed(2)),
            changeType: changeType
        });

    } catch (err: any) {
        console.error("Error fetching expenses stats:", err);
        res.status(500).json({ error: "Failed to fetch expenses statistics.", detail: err.message });
    }
});

// Example SQL for Profitability Endpoint (GET /api/stats/profitability?startDate=...&endDate=...)
// Example SQL for Profitability Endpoint (GET /api/stats/profitability?startDate=...&endDate=...)
app.get("/api/stats/profitability", authMiddleware, async (req, res) => {
    const userId = req.user!.parent_user_id;
    const startDate = req.query.startDate as string | undefined;
    const endDate = req.query.endDate as string | undefined;

    try {
        // --- Current Period Profitability (Net Income) ---
        // --- FIXED: Use reporting_categories to filter for specific IS sections ---
        let currentQuery = `
            SELECT
                COALESCE(SUM(CASE
                    WHEN rc.section = 'revenue' THEN jl.credit -- Only 'revenue' section credits
                    ELSE 0
                END), 0)::numeric(14, 2) AS total_revenue,
                COALESCE(SUM(CASE
                    WHEN rc.section = 'operating_expenses' THEN jl.debit -- Only 'operating_expenses' section debits (adjust section name if needed)
                    ELSE 0
                END), 0)::numeric(14, 2) AS total_expenses
            FROM public.journal_lines jl
            JOIN public.journal_entries je ON jl.entry_id = je.id AND jl.user_id = je.user_id
            JOIN public.accounts a ON jl.account_id = a.id AND jl.user_id = a.user_id
            JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id -- Added JOIN
            WHERE je.user_id = $1
              AND rc.statement = 'income_statement'                           -- Filter for IS
              AND rc.section IN ('revenue', 'operating_expenses')            -- Specific sections (adjust if needed)
              AND je.entry_date >= $2
              AND je.entry_date <= $3
        `;
        let currentParams: any[] = [userId, '1970-01-01', '9999-12-31'];
        if (startDate) currentParams[1] = startDate;
        if (endDate) currentParams[2] = endDate;

        const currentResult = await pool.query(currentQuery, currentParams);
        const currentRevenue = parseFloat(currentResult.rows[0]?.total_revenue) || 0;
        const currentExpenses = parseFloat(currentResult.rows[0]?.total_expenses) || 0;
        const currentProfit = currentRevenue - currentExpenses;

        // --- Previous Period Profitability (Net Income) ---
        // --- FIXED: Use reporting_categories for previous period too ---
        let previousQuery = `
            SELECT
                COALESCE(SUM(CASE
                    WHEN rc.section = 'revenue' THEN jl.credit
                    ELSE 0
                END), 0)::numeric(14, 2) AS total_revenue,
                COALESCE(SUM(CASE
                    WHEN rc.section = 'operating_expenses' THEN jl.debit -- Adjust section name if needed
                    ELSE 0
                END), 0)::numeric(14, 2) AS total_expenses
            FROM public.journal_lines jl
            JOIN public.journal_entries je ON jl.entry_id = je.id AND jl.user_id = je.user_id
            JOIN public.accounts a ON jl.account_id = a.id AND jl.user_id = a.user_id
            JOIN public.reporting_categories rc ON rc.id = a.reporting_category_id -- Added JOIN
            WHERE je.user_id = $1
              AND rc.statement = 'income_statement'                             -- Filter for IS
              AND rc.section IN ('revenue', 'operating_expenses')              -- Specific sections (adjust if needed)
              AND je.entry_date >= $2
              AND je.entry_date < $3
        `;
        // Calculate previous period dates
        let previousParams: any[] = [userId, '1970-01-01', currentParams[1]];

        if (startDate && endDate) {
             const start = new Date(startDate);
             const end = new Date(endDate);
             const diffTime = Math.abs(end.getTime() - start.getTime());
             const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;

             const previousEnd = new Date(start.getTime() - 1000 * 60 * 60 * 24);
             const previousStart = new Date(previousEnd.getTime() - diffTime);

             previousParams = [userId, previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]];
        } else if (startDate) {
            const start = new Date(startDate);
            const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
            const previousEnd = new Date(start.getTime() - 1000 * 60 * 60 * 24);
            const previousStart = new Date(previousEnd.getTime() - thirtyDaysMs);
            previousParams = [userId, previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]];
        }

        const previousResult = await pool.query(previousQuery, previousParams);
        const previousRevenue = parseFloat(previousResult.rows[0]?.total_revenue) || 0;
        const previousExpenses = parseFloat(previousResult.rows[0]?.total_expenses) || 0;
        const previousProfit = previousRevenue - previousExpenses;

        // --- Calculate Change for Profit ---
        let changePercentage = 0;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';
        if (previousProfit !== 0) {
            changePercentage = ((currentProfit - previousProfit) / Math.abs(previousProfit)) * 100;
            changeType = changePercentage > 0 ? 'increase' : changePercentage < 0 ? 'decrease' : 'neutral';
        } else if (currentProfit > 0) {
             changeType = 'increase';
        } else if (currentProfit < 0) {
             changeType = 'decrease';
        }

        res.json({
            value: currentProfit, // Net Profit/Loss
            previousValue: previousProfit,
            changePercentage: parseFloat(changePercentage.toFixed(2)),
            changeType: changeType
        });

    } catch (err: any) {
        console.error("Error fetching profitability stats:", err);
        res.status(500).json({ error: "Failed to fetch profitability statistics.", detail: err.message });
    }
});

// Helper function to calculate previous period dates based on the current period


// NEW ENDPOINT: GET Revenue Statistics for a period (or all time)
{/*app.get('/api/stats/revenue', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    // startDate and endDate can now be optional
    const { startDate, endDate } = req.query as { startDate?: string; endDate?: string };

    try {
        let currentPeriodValue = 0;
        let previousPeriodValue = 0;
        let changePercentage: number | undefined;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';

        let dateFilterClause = '';
        const currentQueryParams: (string | number)[] = [user_id];
        let currentParamIndex = 2;

        // If both startDate and endDate are provided, build the date filter clause
        if (startDate && endDate) {
            dateFilterClause = ` AND date BETWEEN $${currentParamIndex++} AND $${currentParamIndex++}`;
            currentQueryParams.push(startDate);
            currentQueryParams.push(endDate);
        }

        // Fetch current period revenue (or all-time if no dates provided)
        const currentRevenueResult = await pool.query(`
            SELECT COALESCE(SUM(amount), 0) AS value
            FROM public.transactions
            WHERE
                user_id = $1
                AND type = 'income'
                AND category IN ('Revenue', 'Sales Revenue')
                ${dateFilterClause};
        `, currentQueryParams);

        currentPeriodValue = parseFloat(currentRevenueResult.rows[0]?.value || 0);

        // Only calculate previous period and change if a specific date range was provided
        if (startDate && endDate) {
            const { prevStartDate, prevEndDate } = getPreviousPeriodDates(startDate, endDate);
            const previousQueryParams: (string | number)[] = [user_id, prevStartDate, prevEndDate];

            // Fetch previous period revenue
            const previousRevenueResult = await pool.query(`
                SELECT COALESCE(SUM(amount), 0) AS value
                FROM public.transactions
                WHERE
                    user_id = $1
                    AND type = 'income'
                    AND category IN ('Revenue', 'Sales Revenue')
                    AND date BETWEEN $2 AND $3;
            `, previousQueryParams);

            previousPeriodValue = parseFloat(previousRevenueResult.rows[0]?.value || 0);

            // Calculate change percentage
            if (previousPeriodValue !== 0) {
                changePercentage = ((currentPeriodValue - previousPeriodValue) / previousPeriodValue) * 100;
                if (changePercentage > 0) {
                    changeType = 'increase';
                } else if (changePercentage < 0) {
                    changeType = 'decrease';
                }
            } else if (currentPeriodValue > 0) {
                changePercentage = 100; // Infinite increase from zero to a positive value
                changeType = 'increase';
            }
        }

        res.json({
            value: currentPeriodValue,
            previousValue: previousPeriodValue,
            changePercentage: changePercentage !== undefined ? parseFloat(changePercentage.toFixed(2)) : undefined,
            changeType: changeType
        });

    } catch (error: unknown) {
        console.error('Error fetching revenue stats:', error);
        res.status(500).json({ error: 'Failed to fetch revenue statistics', detail: error instanceof Error ? error.message : String(error) });
    }
});

// NEW ENDPOINT: GET Expenses Statistics for a period (or all time)
app.get('/api/stats/expenses', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    // startDate and endDate can now be optional
    const { startDate, endDate } = req.query as { startDate?: string; endDate?: string };

    try {
        let currentPeriodValue = 0;
        let previousPeriodValue = 0;
        let changePercentage: number | undefined;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';

        let dateFilterClause = '';
        const currentQueryParams: (string | number)[] = [user_id];
        let currentParamIndex = 2;

        // If both startDate and endDate are provided, build the date filter clause
        if (startDate && endDate) {
            dateFilterClause = ` AND date BETWEEN $${currentParamIndex++} AND $${currentParamIndex++}`;
            currentQueryParams.push(startDate);
            currentQueryParams.push(endDate);
        }

        // Fetch current period expenses (or all-time if no dates provided)
        const currentExpensesResult = await pool.query(`
            SELECT COALESCE(SUM(amount), 0) AS value
            FROM public.transactions
            WHERE
                user_id = $1
                AND type = 'expense'
                ${dateFilterClause};
        `, currentQueryParams);

        currentPeriodValue = parseFloat(currentExpensesResult.rows[0]?.value || 0);

        // Only calculate previous period and change if a specific date range was provided
        if (startDate && endDate) {
            const { prevStartDate, prevEndDate } = getPreviousPeriodDates(startDate, endDate);
            const previousQueryParams: (string | number)[] = [user_id, prevStartDate, prevEndDate];

            // Fetch previous period expenses
            const previousExpensesResult = await pool.query(`
                SELECT COALESCE(SUM(amount), 0) AS value
                FROM public.transactions
                WHERE
                    user_id = $1
                    AND type = 'expense'
                    AND date BETWEEN $2 AND $3;
            `, previousQueryParams);

            previousPeriodValue = parseFloat(previousExpensesResult.rows[0]?.value || 0);

            // Calculate change percentage
            if (previousPeriodValue !== 0) {
                changePercentage = ((currentPeriodValue - previousPeriodValue) / previousPeriodValue) * 100;
                if (changePercentage > 0) { // For expenses, an increase is often seen as a negative trend
                    changeType = 'increase';
                } else if (changePercentage < 0) {
                    changeType = 'decrease';
                }
            } else if (currentPeriodValue > 0) {
                changePercentage = 100; // Infinite increase from zero to a positive value
                changeType = 'increase';
            }
        }

        res.json({
            value: currentPeriodValue,
            previousValue: previousPeriodValue,
            changePercentage: changePercentage !== undefined ? parseFloat(changePercentage.toFixed(2)) : undefined,
            changeType: changeType
        });

    } catch (error: unknown) {
        console.error('Error fetching expenses stats:', error);
        res.status(500).json({ error: 'Failed to fetch expenses statistics', detail: error instanceof Error ? error.message : String(error) });
    }
});

// Existing /api/stats/clients endpoint, modified to allow all-time view and use public.sales
app.get('/api/stats/clients', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    // startDate and endDate can now be optional
    const { startDate, endDate } = req.query as { startDate?: string; endDate?: string };

    try {
        let currentPeriodCount = 0;
        let previousPeriodCount = 0;
        let changePercentage: number | undefined;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';

        let dateFilterClause = '';
        const currentQueryParams: (string | number)[] = [user_id];
        let currentParamIndex = 2;

        // If both startDate and endDate are provided, build the date filter clause for 'created_at'
        if (startDate && endDate) {
            dateFilterClause = ` AND created_at BETWEEN $${currentParamIndex++} AND $${currentParamIndex++}`;
            currentQueryParams.push(startDate);
            currentQueryParams.push(endDate);
        }

        // Fetch current period client count (or all-time if no dates provided)
        // Now counting distinct customer_id from public.sales table
        const currentClientsResult = await pool.query(`
            SELECT COUNT(DISTINCT customer_id) AS count
            FROM public.sales
            WHERE user_id = $1
            ${dateFilterClause};
        `, currentQueryParams);
        currentPeriodCount = parseInt(currentClientsResult.rows[0]?.count || 0, 10);

        // Only calculate previous period and change if a specific date range was provided
        if (startDate && endDate) {
            const { prevStartDate, prevEndDate } = getPreviousPeriodDates(startDate, endDate);
            const previousQueryParams: (string | number)[] = [user_id, prevStartDate, prevEndDate];

            // Fetch previous period client count
            // Now counting distinct customer_id from public.sales table
            const previousClientsResult = await pool.query(`
                SELECT COUNT(DISTINCT customer_id) AS count
                FROM public.sales
                WHERE user_id = $1
                AND created_at BETWEEN $2 AND $3;
            `, previousQueryParams);
            previousPeriodCount = parseInt(previousClientsResult.rows[0]?.count || 0, 10);

            // Calculate change percentage
            if (previousPeriodCount !== 0) {
                changePercentage = ((currentPeriodCount - previousPeriodCount) / previousPeriodCount) * 100;
                if (changePercentage > 0) {
                    changeType = 'increase';
                } else if (changePercentage < 0) {
                    changeType = 'decrease';
                }
            } else if (currentPeriodCount > 0) {
                changePercentage = 100; // Infinite increase from zero to a positive value
                changeType = 'increase';
            }
        }

        res.json({
            count: currentPeriodCount,
            previousCount: previousPeriodCount,
            changePercentage: changePercentage !== undefined ? parseFloat(changePercentage.toFixed(2)) : undefined,
            changeType: changeType
        });

    } catch (error: unknown) {
        console.error('Error fetching client stats:', error);
        res.status(500).json({ error: 'Failed to fetch client statistics', detail: error instanceof Error ? error.message : String(error) });
    }
});


// Add this new endpoint to your server.ts file, e.g., after the quotes endpoint.
app.get('/api/stats/profitability', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.parent_user_id;
  const { startDate, endDate } = req.query;

  try {
    let dateFilter = '';
    const queryParams: (string | number)[] = [user_id];
    let paramIndex = 2;

    if (startDate) {
      dateFilter += ` AND date >= $${paramIndex++}`;
      queryParams.push(startDate as string);
    }
    if (endDate) {
      dateFilter += ` AND date <= $${paramIndex++}`;
      queryParams.push(endDate as string);
    }

    // Get total income
    const incomeResult = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_income FROM public.transactions WHERE user_id = $1 AND type = 'income' ${dateFilter};`,
      queryParams
    );
    const totalIncome = parseFloat(incomeResult.rows[0]?.total_income || 0);

    // Get total expenses
    const expensesResult = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM public.transactions WHERE user_id = $1 AND type = 'expense' ${dateFilter};`,
      queryParams
    );
    const totalExpenses = parseFloat(expensesResult.rows[0]?.total_expenses || 0);

    // Get previous period income
    const { currentStart, previousStart, previousEnd } = getCurrentAndPreviousDateRanges();

    const previousIncomeResult = await pool.query(
        `SELECT COALESCE(SUM(amount), 0) AS total_income FROM public.transactions WHERE user_id = $1 AND type = 'income' AND date >= $2 AND date < $3;`,
        [user_id, previousStart, currentStart]
    );
    const previousIncome = parseFloat(previousIncomeResult.rows[0]?.total_income || 0);

    // Get previous period expenses
    const previousExpensesResult = await pool.query(
        `SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM public.transactions WHERE user_id = $1 AND type = 'expense' AND date >= $2 AND date < $3;`,
        [user_id, previousStart, currentStart]
    );
    const previousExpenses = parseFloat(previousExpensesResult.rows[0]?.total_expenses || 0);


    const currentProfit = totalIncome - totalExpenses;
    const previousProfit = previousIncome - previousExpenses;
    const { changePercentage, changeType } = calculateChange(currentProfit, previousProfit);

    res.status(200).json({
      value: currentProfit,
      previousValue: previousProfit,
      changePercentage,
      changeType,
    });
  } catch (error) {
    console.error('Error fetching profitability stats:', error);
    res.status(500).json({ error: 'Failed to fetch profitability stats.' });
  }
});*/}

app.get('/api/stats/clients', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id;
    // startDate and endDate can now be optional
    const { startDate, endDate } = req.query as { startDate?: string; endDate?: string };

    try {
        let currentPeriodCount = 0;
        let previousPeriodCount = 0;
        let changePercentage: number | undefined;
        let changeType: 'increase' | 'decrease' | 'neutral' = 'neutral';

        let dateFilterClause = '';
        const currentQueryParams: (string | number)[] = [user_id];
        let currentParamIndex = 2;

        // If both startDate and endDate are provided, build the date filter clause for 'created_at'
        if (startDate && endDate) {
            dateFilterClause = ` AND created_at BETWEEN $${currentParamIndex++} AND $${currentParamIndex++}`;
            currentQueryParams.push(startDate);
            currentQueryParams.push(endDate);
        }

        // Fetch current period client count (or all-time if no dates provided)
        // Now counting distinct customer_id from public.sales table
        const currentClientsResult = await pool.query(`
            SELECT COUNT(DISTINCT customer_id) AS count
            FROM public.sales
            WHERE user_id = $1
            ${dateFilterClause};
        `, currentQueryParams);
        currentPeriodCount = parseInt(currentClientsResult.rows[0]?.count || 0, 10);

        // Only calculate previous period and change if a specific date range was provided
        if (startDate && endDate) {
            const { prevStartDate, prevEndDate } = getPreviousPeriodDates(startDate, endDate);
            const previousQueryParams: (string | number)[] = [user_id, prevStartDate, prevEndDate];

            // Fetch previous period client count
            // Now counting distinct customer_id from public.sales table
            const previousClientsResult = await pool.query(`
                SELECT COUNT(DISTINCT customer_id) AS count
                FROM public.sales
                WHERE user_id = $1
                AND created_at BETWEEN $2 AND $3;
            `, previousQueryParams);
            previousPeriodCount = parseInt(previousClientsResult.rows[0]?.count || 0, 10);

            // Calculate change percentage
            if (previousPeriodCount !== 0) {
                changePercentage = ((currentPeriodCount - previousPeriodCount) / previousPeriodCount) * 100;
                if (changePercentage > 0) {
                    changeType = 'increase';
                } else if (changePercentage < 0) {
                    changeType = 'decrease';
                }
            } else if (currentPeriodCount > 0) {
                changePercentage = 100; // Infinite increase from zero to a positive value
                changeType = 'increase';
            }
        }

        res.json({
            count: currentPeriodCount,
            previousCount: previousPeriodCount,
            changePercentage: changePercentage !== undefined ? parseFloat(changePercentage.toFixed(2)) : undefined,
            changeType: changeType
        });

    } catch (error: unknown) {
        console.error('Error fetching client stats:', error);
        res.status(500).json({ error: 'Failed to fetch client statistics', detail: error instanceof Error ? error.message : String(error) });
    }
});


// --- END NEW ENDPOINT ---
// GET /api/my-agents - Fetch all users with the 'agent' role directly under the authenticated user
// GET /api/my-agents - Fetch agents with core user info and some agent-specific info
app.get('/api/my-agents', authMiddleware, async (req: Request, res: Response) => {
  const superAgentUserId = req.user!.user_id; // ID of the logged-in Super Agent

  try {
    // Join users, user_roles, roles (for filtering) and agents (for specific data)
    const { rows } = await pool.query(
      `SELECT u.id, u.name AS "displayName", u.email, u.user_id,
              COALESCE(json_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '[]') AS roles,
              a.commission_rate, a.territory, a.agent_code -- Example agent-specific fields
       FROM public.users u
       LEFT JOIN public.user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN public.roles r ON ur.role = r.name
       LEFT JOIN public.agents a ON u.user_id = a.user_id -- Join with agents table
       WHERE u.parent_user_id = $1
         AND LOWER(r.name) = 'agent'
       GROUP BY u.id, u.name, u.email, u.user_id, a.commission_rate, a.territory, a.agent_code -- Include agent fields in GROUP BY
       ORDER BY u.name`,
      [superAgentUserId]
    );
    res.json(rows);
  } catch (error: unknown) {
    console.error('Error fetching agents:', error);
    res.status(500).json({ error: 'Failed to fetch agents.', detail: error instanceof Error ? error.message : String(error) });
  }
});


// EDIT/UPDATE AGENT ENDPOINT
// EDIT/UPDATE AGENT ENDPOINT
// EDIT/UPDATE AGENT ENDPOINT
app.patch('/api/agents/:user_id', authMiddleware, async (req: Request, res: Response) => {
  const superAgentUserId = req.user!.user_id; // ID of the logged-in Super Agent
  const targetUserId = req.params.user_id; // User ID of the agent to update
  const updates = req.body; // Fields to update

  try {
    // First, verify that the agent belongs to this super agent
    const agentCheck = await pool.query(
      `SELECT 1 FROM public.users 
       WHERE user_id = $1 AND parent_user_id = $2`,
      [targetUserId, superAgentUserId]
    );

    if (agentCheck.rowCount === 0) {
      return res.status(403).json({ 
        error: 'Access denied. Agent does not belong to you.' 
      });
    }

    // Start transaction
    await pool.query('BEGIN');

    // Update user information (name, email)
    if (updates.displayName || updates.email) {
      const userUpdates: string[] = [];
      const userValues: any[] = [];
      let userValueIndex = 1;

      if (updates.displayName) {
        userUpdates.push(`name = $${userValueIndex}`);
        userValues.push(updates.displayName);
        userValueIndex++;
      }

      if (updates.email) {
        userUpdates.push(`email = $${userValueIndex}`);
        userValues.push(updates.email);
        userValueIndex++;
      }

      userValues.push(targetUserId);

      await pool.query(
        `UPDATE public.users 
         SET ${userUpdates.join(', ')} 
         WHERE user_id = $${userValueIndex}`,
        userValues
      );
    }

    // Update agent-specific information
    if (
      updates.commission_rate !== undefined || 
      updates.territory !== undefined || 
      updates.agent_code !== undefined ||
      updates.target_monthly_registrations !== undefined ||
      updates.target_monthly_sales !== undefined ||
      updates.performance_score !== undefined
    ) {
      // First, check if agent record exists
      const agentExists = await pool.query(
        'SELECT user_id FROM public.agents WHERE user_id = $1',
        [targetUserId]
      );

      if (agentExists && agentExists.rowCount && agentExists.rowCount > 0) {
        // Update existing agent record
        const agentUpdates: string[] = [];
        const agentValues: any[] = [];
        let agentValueIndex = 1;

        if (updates.commission_rate !== undefined) {
          agentUpdates.push(`commission_rate = $${agentValueIndex}`);
          agentValues.push(updates.commission_rate);
          agentValueIndex++;
        }

        if (updates.territory !== undefined) {
          agentUpdates.push(`territory = $${agentValueIndex}`);
          agentValues.push(updates.territory);
          agentValueIndex++;
        }

        if (updates.agent_code !== undefined) {
          agentUpdates.push(`agent_code = $${agentValueIndex}`);
          agentValues.push(updates.agent_code);
          agentValueIndex++;
        }

        if (updates.target_monthly_registrations !== undefined) {
          agentUpdates.push(`target_monthly_registrations = $${agentValueIndex}`);
          agentValues.push(updates.target_monthly_registrations);
          agentValueIndex++;
        }

        if (updates.target_monthly_sales !== undefined) {
          agentUpdates.push(`target_monthly_sales = $${agentValueIndex}`);
          agentValues.push(updates.target_monthly_sales);
          agentValueIndex++;
        }

        if (updates.performance_score !== undefined) {
          agentUpdates.push(`performance_score = $${agentValueIndex}`);
          agentValues.push(updates.performance_score);
          agentValueIndex++;
        }

        // Don't update parent_user_id as it should remain unchanged
        agentValues.push(targetUserId);

        if (agentUpdates.length > 0) {
          await pool.query(
            `UPDATE public.agents 
             SET ${agentUpdates.join(', ')} 
             WHERE user_id = $${agentValueIndex}`,
            agentValues
          );
        }
      } else {
        // Insert new agent record - but we need to get the parent_user_id
        // The parent_user_id should be the superAgentUserId
        const agentFields: string[] = ['user_id', 'parent_user_id'];
        const agentValues: any[] = [targetUserId, superAgentUserId];
        let agentValueIndex = 3; // Starting from 3 since we already have 2 values

        if (updates.commission_rate !== undefined) {
          agentFields.push('commission_rate');
          agentValues.push(updates.commission_rate);
          agentValueIndex++;
        }

        if (updates.territory !== undefined) {
          agentFields.push('territory');
          agentValues.push(updates.territory);
          agentValueIndex++;
        }

        if (updates.agent_code !== undefined) {
          agentFields.push('agent_code');
          agentValues.push(updates.agent_code);
          agentValueIndex++;
        }

        if (updates.target_monthly_registrations !== undefined) {
          agentFields.push('target_monthly_registrations');
          agentValues.push(updates.target_monthly_registrations);
          agentValueIndex++;
        }

        if (updates.target_monthly_sales !== undefined) {
          agentFields.push('target_monthly_sales');
          agentValues.push(updates.target_monthly_sales);
          agentValueIndex++;
        }

        if (updates.performance_score !== undefined) {
          agentFields.push('performance_score');
          agentValues.push(updates.performance_score);
          agentValueIndex++;
        }

        const placeholders = agentValues.map((_, i) => `$${i + 1}`).join(', ');
        
        await pool.query(
          `INSERT INTO public.agents (${agentFields.join(', ')}) 
           VALUES (${placeholders})`,
          agentValues
        );
      }
    }

    // Commit transaction
    await pool.query('COMMIT');

    res.json({ message: 'Agent updated successfully' });
  } catch (error: unknown) {
    // Rollback transaction on error
    await pool.query('ROLLBACK');
    console.error('Error updating agent:', error);
    res.status(500).json({ 
      error: 'Failed to update agent.', 
      detail: error instanceof Error ? error.message : String(error) 
    });
  }
});

// DELETE AGENT ENDPOINT
app.delete('/api/agents/:user_id', authMiddleware, async (req: Request, res: Response) => {
  const superAgentUserId = req.user!.user_id; // ID of the logged-in Super Agent
  const targetUserId = req.params.user_id; // User ID of the agent to delete

  try {
    // Verify that the agent belongs to this super agent
    const agentCheck = await pool.query(
      `SELECT 1 FROM public.users 
       WHERE user_id = $1 AND parent_user_id = $2`,
      [targetUserId, superAgentUserId]
    );

    if (agentCheck.rowCount === 0) {
      return res.status(403).json({ 
        error: 'Access denied. Agent does not belong to you.' 
      });
    }

    // Start transaction
    await pool.query('BEGIN');

    // Delete from agents table first (foreign key constraint)
    await pool.query('DELETE FROM public.agents WHERE user_id = $1', [targetUserId]);

    // Delete from user_roles table
    await pool.query('DELETE FROM public.user_roles WHERE user_id = $1', [targetUserId]);

    // Delete from users table
    await pool.query('DELETE FROM public.users WHERE user_id = $1', [targetUserId]);

    // Commit transaction
    await pool.query('COMMIT');

    res.json({ message: 'Agent deleted successfully' });
  } catch (error: unknown) {
    // Rollback transaction on error
    await pool.query('ROLLBACK');
    console.error('Error deleting agent:', error);
    res.status(500).json({ 
      error: 'Failed to delete agent.', 
      detail: error instanceof Error ? error.message : String(error) 
    });
  }
});
// server.ts or your routes file
// server.ts or your routes file
// GET /api/super-agent/dashboard/stats - Fetch dashboard statistics for the super agent
// server.ts or your routes file
// GET /api/super-agent/dashboard/stats - Fetch dashboard statistics for the super agent
app.get('/api/super-agent/dashboard/stats', authMiddleware, async (req: Request, res: Response) => {
  // Use req.user!.user_id to get the ID of the currently logged-in Super Agent
  const superAgentUserId = req.user!.user_id;

  if (!superAgentUserId) {
      return res.status(401).json({ error: 'Unauthorized: Super Agent User ID not found.' });
  }

  try {
    // --- Fetch Dashboard Statistics ---

    // 1. Total Agents (users with role 'agent' and parent_user_id = superAgentUserId)
    // Using LOWER for case-insensitive comparison as per previous discussions
    const agentCountResult = await pool.query(
      `SELECT COUNT(*) AS count FROM public.users u
       JOIN public.user_roles ur ON u.user_id = ur.user_id
       WHERE u.parent_user_id = $1 AND LOWER(ur.role) = 'agent'`,
      [superAgentUserId]
    );
    const totalAgents = parseInt(agentCountResult.rows[0]?.count || '0', 10);

    // 2. Total Registrations (applications where parent_user_id = superAgentUserId)
    // Using the newly added parent_user_id column for efficient lookup
    const regCountResult = await pool.query(
       `SELECT COUNT(*) AS count FROM public.applications a
        WHERE a.parent_user_id = $1`,
       [superAgentUserId]
    );
    const totalRegistrations = parseInt(regCountResult.rows[0]?.count || '0', 10);

    // 3. Total Successful Payments
    // Based on sales table schema: Any record with a payment_type is considered an attempt.
    // Adjust condition if you have a stricter definition (e.g., exclude certain types or check amounts).
    const successfulPaymentsResult = await pool.query(
       `SELECT COUNT(*) AS count FROM public.sales s
        JOIN public.users u ON s.teller_id = u.user_id
        WHERE u.parent_user_id = $1 AND s.payment_type IN ('Cash', 'Bank', 'Credit')`, // Use payment_type
       [superAgentUserId]
    );
    const totalSuccessfulPayments = parseInt(successfulPaymentsResult.rows[0]?.count || '0', 10);

    // 4. Total Commission Earned
    // Example: Calculate 5% commission on total_amount for successful sales.
    // Adjust calculation logic and percentage as needed.
    const commissionResult = await pool.query(
       `SELECT COALESCE(SUM(s.total_amount * 0.05), 0)::numeric(14, 2) AS total_commission FROM public.sales s
        JOIN public.users u ON s.teller_id = u.user_id
        WHERE u.parent_user_id = $1 AND s.payment_type IN ('Cash', 'Bank', 'Credit')`, // Use payment_type
       [superAgentUserId]
    );
    const totalCommissionEarned = parseFloat(commissionResult.rows[0]?.total_commission || '0');

    // 5. Pending Payments
    // Example logic: Credit sales with remaining amount.
    // Adjust based on your business definition of "pending".
    const pendingPaymentsResult = await pool.query(
       `SELECT COUNT(*) AS count FROM public.sales s
        JOIN public.users u ON s.teller_id = u.user_id
        WHERE u.parent_user_id = $1 AND s.payment_type = 'Credit' AND COALESCE(s.remaining_credit_amount, 0) > 0`,
       [superAgentUserId]
    );
    const totalPendingPayments = parseInt(pendingPaymentsResult.rows[0]?.count || '0', 10);

    // 6. Failed Payments
    // The sales table doesn't explicitly track failed payments.
    // Placeholder query that returns 0. You need to define what constitutes "failed"
    // based on your application logic (e.g., separate table, specific flags).
    const failedPaymentsResult = await pool.query(
       `SELECT COUNT(*) AS count FROM public.sales s
        JOIN public.users u ON s.teller_id = u.user_id
        WHERE u.parent_user_id = $1 AND 1=0`, // Always false, returns 0 count
       [superAgentUserId]
    );
    const totalFailedPayments = parseInt(failedPaymentsResult.rows[0]?.count || '0', 10);

    // --- End Fetching Statistics ---

    res.json({
      totalAgents,
      totalRegistrations,
      totalSuccessfulPayments,
      totalPendingPayments,
      totalFailedPayments,
      totalCommissionEarned,
      // ... other stats
    });
  } catch (error: unknown) {
    console.error('Error fetching super agent dashboard stats:', error);
    res.status(500).json({
      error: 'Failed to fetch dashboard statistics.',
      detail: error instanceof Error ? error.message : String(error),
    });
  }
});



// GET /api/super-agent/dashboard/chart-data - Fetch chart data for the super agent dashboard
app.get('/api/super-agent/dashboard/chart-data', authMiddleware, async (req: Request, res: Response) => {
  // Use req.user!.user_id to get the ID of the currently logged-in Super Agent
  const superAgentUserId = req.user!.user_id;
  const period = req.query.period as string | undefined;

  if (!superAgentUserId) {
      return res.status(401).json({ error: 'Unauthorized: Super Agent User ID not found.' });
  }

  // Validate period parameter if needed (e.g., only allow 'last_5_months')
  if (period !== 'last_5_months') { // Example validation
     // You could also provide a default or handle other periods
     return res.status(400).json({ error: 'Invalid or unsupported period parameter.' });
  }

  try {
    // --- Logic to fetch and aggregate chart data ---

    // Dynamically calculate the last 5 months labels
    const last5MonthsLabels: string[] = [];
    const now = new Date();
    for (let i = 4; i >= 0; i--) {
      const monthDate = new Date(now.getFullYear(), now.getMonth() - i, 1);
      // Format to short month name (e.g., "Oct")
      last5MonthsLabels.push(monthDate.toLocaleString('default', { month: 'short' }));
    }

    // Initialize data arrays
    const monthlyRegistrations: number[] = new Array(5).fill(0);
    const monthlyPayments: number[] = new Array(5).fill(0); // Initialize with 5 elements

    // --- Fetch and Aggregate Data ---

    // 1. Fetch Registration Data (Grouped by Month)
    // Using the parent_user_id column in applications
    const regTrendQuery = `
      SELECT
        EXTRACT(MONTH FROM a.created_at) as month_num,
        EXTRACT(YEAR FROM a.created_at) as year_num,
        COUNT(*) as count
      FROM public.applications a
      WHERE a.parent_user_id = $1
        AND a.created_at >= CURRENT_DATE - INTERVAL '5 months'
      GROUP BY year_num, month_num
      ORDER BY year_num, month_num
    `;
    const regTrendResult = await pool.query(regTrendQuery, [superAgentUserId]);

    // Map registration results to the correct month index in our array
    regTrendResult.rows.forEach(row => {
        const dataYear = parseInt(row.year_num, 10);
        const dataMonthZeroBased = parseInt(row.month_num, 10) - 1; // JS months are 0-based
        const dataDate = new Date(dataYear, dataMonthZeroBased, 1);

        // Find the index in our last5MonthsLabels array
        for (let i = 0; i < 5; i++) {
            const labelDate = new Date(now.getFullYear(), now.getMonth() - (4 - i), 1);
            if (dataDate.getFullYear() === labelDate.getFullYear() &&
                dataDate.getMonth() === labelDate.getMonth()) {
                monthlyRegistrations[i] = parseInt(row.count, 10);
                break; // Found the month, exit the loop
            }
        }
    });

    // 2. Fetch Payment Data (Grouped by Month)
    // Example using 'sales' table with 'teller_id' and 'payment_type'
    // Counts sales with any valid payment_type for the trend.
    const paymentTrendQuery = `
      SELECT
        EXTRACT(MONTH FROM s.created_at) as month_num,
        EXTRACT(YEAR FROM s.created_at) as year_num,
        COUNT(*) as count -- Or SUM(total_amount) if you want total value
      FROM public.sales s
      JOIN public.users u ON s.teller_id = u.user_id -- Join to filter by agent hierarchy
      WHERE u.parent_user_id = $1
        AND s.payment_type IN ('Cash', 'Bank', 'Credit') -- Use payment_type
        AND s.created_at >= CURRENT_DATE - INTERVAL '5 months'
      GROUP BY year_num, month_num
      ORDER BY year_num, month_num
    `;
    const paymentTrendResult = await pool.query(paymentTrendQuery, [superAgentUserId]);

     // Map payment results to the correct month index in our array
    paymentTrendResult.rows.forEach(row => {
        const dataYear = parseInt(row.year_num, 10);
        const dataMonthZeroBased = parseInt(row.month_num, 10) - 1; // JS months are 0-based
        const dataDate = new Date(dataYear, dataMonthZeroBased, 1);

        // Find the index in our last5MonthsLabels array
        for (let i = 0; i < 5; i++) {
            const labelDate = new Date(now.getFullYear(), now.getMonth() - (4 - i), 1);
            if (dataDate.getFullYear() === labelDate.getFullYear() &&
                dataDate.getMonth() === labelDate.getMonth()) {
                monthlyPayments[i] = parseInt(row.count, 10); // Or parseFloat for SUM(total_amount)
                break; // Found the month, exit the loop
            }
        }
    });

    // --- Format data for the frontend ---
    // Combine labels with data points
    const chartDataFormatted: { month: string; registrations: number; payments: number }[] = last5MonthsLabels.map((label, index) => ({
      month: label,
      registrations: monthlyRegistrations[index] || 0,
      payments: monthlyPayments[index] || 0,
    }));

    // --- End Logic ---
    res.json(chartDataFormatted);
  } catch (error: unknown) {
    console.error('Error fetching super agent dashboard chart data:', error);
    res.status(500).json({
      error: 'Failed to fetch dashboard chart data.',
      detail: error instanceof Error ? error.message : String(error),
    });
  }
});

app.get('/api/clients', authMiddleware, async (req: Request, res: Response) => {
  // Query params
  const rawStatus = (req.query.status as string) || 'all';
  const status = rawStatus.toLowerCase(); // normalize
  const dateRange = (req.query.dateRange as string) || 'all_time';
  const search = req.query.search;

  // From auth middleware (make sure middleware sets req.user properly)
  const agentId = req.user?.parent_user_id; // or req.user?.user_id if that’s how you stored apps
  if (!agentId) {
    return res.status(401).json({ error: 'Unauthenticated or missing parent_user_id on token.' });
  }

  let clientConn: PoolClient | null = null;
  try {
    clientConn = await pool.connect();

    const values: any[] = [agentId];
    let query = `
      SELECT id, name, surname, created_at,  total_amount, id_number
      FROM applications
      WHERE parent_user_id = $1
    `;

    // Date range filter (skip for all_time)
    if (dateRange === 'this_week') {
      query += ` AND created_at >= date_trunc('week', now())`;
    } else if (dateRange === 'this_month') {
      query += ` AND created_at >= date_trunc('month', now())`;
    } else if (dateRange === 'last_month') {
      query += ` AND created_at >= date_trunc('month', now()) - INTERVAL '1 month'
                AND created_at <  date_trunc('month', now())`;
    } else if (dateRange === 'last_3_months') {
      query += ` AND created_at >= date_trunc('month', now()) - INTERVAL '3 months'`;
    }
    // else all_time → no date filter

    // Status filter (only when != 'all')
    if (status !== 'all') {
      values.push(status);
      query += ` AND LOWER(status) = $${values.length}`;
    }

    // Search filter (name, surname, id_number)
    let searchString = '';
    if (typeof search === 'string') searchString = search;
    else if (Array.isArray(search) && typeof search[0] === 'string') searchString = search[0];

    if (searchString) {
      const term = `%${searchString.toLowerCase()}%`;
      // we can reuse the same placeholder index 3x or push it 3 times; reuse is fine
      values.push(term);
      const idx = values.length;
      query += ` AND (LOWER(name) LIKE $${idx} OR LOWER(surname) LIKE $${idx} OR LOWER(id_number) LIKE $${idx})`;
    }

    query += ` ORDER BY created_at DESC`;

    const result = await clientConn.query(query, values);

    const formatted = result.rows.map((row: any) => ({
      id: row.id,
      clientId: row.id_number || 'N/A',
      name: `${row.name ?? ''} ${row.surname ?? ''}`.trim(),
      date: row.created_at ? new Date(row.created_at).toLocaleDateString() : '',
      status: (row.status ?? '').charAt(0).toUpperCase() + (row.status ?? '').slice(1), // e.g. "pending" -> "Pending"
      amount: row.total_amount == null ? 0 : Number(row.total_amount),
    }));

    res.json(formatted);
  } catch (error: any) {
    console.error('Error fetching clients data:', error);
    res.status(500).json({ error: 'Failed to fetch clients data.', detail: error.message });
  } finally {
    clientConn?.release();
  }
});





app.listen(PORT, () => {
  console.log(`Node server running on http://localhost:${PORT}`);
});
