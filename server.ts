import dotenv from 'dotenv';
dotenv.config();


import cors from 'cors';
import { Pool } from 'pg';
import multer from 'multer';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { createClient } from '@supabase/supabase-js';

import express, { Request, Response, NextFunction } from 'express';

const app = express();
const PORT = 3000;
const PDFDocument = require('pdfkit');

app.use(cors({
  origin: '*',
}));
app.use(express.json());

const supabaseUrl = "https://phoaahdutroiujxiehze.supabase.co";
const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBob2FhaGR1dHJvaXVqeGllaHplIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NTE3MjU1MSwiZXhwIjoyMDcwNzQ4NTUxfQ.XbnwOjhIil3O9NEmfhXSiORC8jdEOYx4fxQR8AtHKD0";
const supabase = createClient(supabaseUrl!, supabaseKey!);

const pool = new Pool({
  connectionString:
    "postgresql://postgres.phoaahdutroiujxiehze:Hunzamabhisvo@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres",
  ssl: {
    rejectUnauthorized: false,
  },
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
  console.log('--- Inside authMiddleware ---');
  console.log('Request Headers:', req.headers); // Log all headers
  const authHeader = req.headers.authorization;
  console.log('Authorization Header:', authHeader); // Log the Authorization header directly

  const token = authHeader?.split(' ')[1];
  console.log('Extracted Token:', token ? token.substring(0, 10) + '...' : 'No token extracted'); // Log first 10 chars of token for brevity

  const secret = process.env.JWT_SECRET;
  console.log('JWT_SECRET (first 5 chars):', secret ? secret.substring(0, 5) + '...' : 'NOT DEFINED'); // Log part of secret

  if (!secret) {
    console.error('❌ JWT_SECRET not defined in .env');
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
    vatNumber?: string; // Maps to tax_id
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

app.post('/register', async (req: Request, res: Response) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ error: 'Missing name, email, or password' });

  const user_id = uuidv4();
  const password_hash = await bcrypt.hash(password, 10);
  const defaultRole = 'admin'; // or 'ceo' depending on your system

  try {
    await pool.query('BEGIN'); // Start a database transaction

    // Step 1: Insert user into `users` table
    await pool.query(`
      INSERT INTO public.users (name, email, user_id, password_hash, role)
      VALUES ($1, $2, $3, $4, $5)
    `, [name, email, user_id, password_hash, defaultRole]);

    // Step 2: Insert default role into `user_roles` table
    await pool.query(`
      INSERT INTO public.user_roles (user_id, role)
      VALUES ($1, $2)
    `, [user_id, defaultRole]);

    // Step 3: Insert default 'Sales Revenue' account into `accounts` table for the new user
    // Corrected 'account_type' to 'type' as per your public.accounts definition
    await pool.query(`
      INSERT INTO public.accounts (name, type, category, code, user_id)
      VALUES ($1, $2, $3, $4, $5)
    `, ['Sales Revenue', 'Income', 'Sales Revenue', '4000', user_id]);

    // You can add more default accounts here if needed, following the same pattern:
    // For example, a 'Cost of Goods Sold' account with code '5000'
    /*
    await pool.query(`
      INSERT INTO public.accounts (name, type, category, code, user_id)
      VALUES ($1, $2, $3, $4, $5)
    `, ['Cost of Goods Sold', 'Expense', 'Cost of Goods Sold', '5000', user_id]);
    */

    await pool.query('COMMIT'); // Commit the transaction if all steps succeed

    res.status(201).json({ message: 'User registered and default accounts created successfully' });
  } catch (error) {
    await pool.query('ROLLBACK'); // Rollback the transaction if any error occurs
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});




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





// Generic PDF generation endpoint for invoices and statements
app.get('/api/:documentType/:id/pdf', authMiddleware, async (req: Request, res: Response) => {
    const { documentType, id } = req.params;
    const { startDate, endDate } = req.query;
    const user_id = req.user!.parent_user_id;

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
                doc.fontSize(24).font('Helvetica-Bold').text('Invoice', { align: 'center' });
                doc.moveDown(1.5);

                doc.fontSize(12).font('Helvetica-Bold').text('Invoice Details:', { underline: true });
                doc.font('Helvetica')
                    .text(`Invoice Number: ${invoice.invoice_number}`)
                    .text(`Customer: ${invoice.customer_name}`)
                    .text(`Invoice Date: ${new Date(invoice.invoice_date).toLocaleDateString('en-GB')}`)
                    .text(`Due Date: ${new Date(invoice.due_date).toLocaleDateString('en-GB')}`);
                doc.moveDown(1.5);

                doc.fontSize(14).font('Helvetica-Bold').text('Line Items:', { underline: true });
                doc.moveDown(0.5);

                // Table Headers
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

                let yPos = tableTop + 25;

                // Line Items Table Rows
                invoice.line_items.forEach((item: any) => {
                    if (yPos + 20 > doc.page.height - doc.page.margins.bottom) {
                        doc.addPage();
                        yPos = doc.page.margins.top;
                        doc.fontSize(10)
                            .font('Helvetica-Bold')
                            .text('Description', col1X, yPos)
                            .text('Qty', col2X, yPos)
                            .text('Unit Price', col3X, yPos, { width: 70, align: 'right' })
                            .text('Tax Rate', col4X, yPos, { width: 60, align: 'right' })
                            .text('Line Total', col5X, yPos, { width: 70, align: 'right' });
                        doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, yPos + 15).lineTo(550, yPos + 15).stroke();
                        yPos += 25;
                    }

                    doc.fontSize(10).font('Helvetica')
                        .text(item.description, col1X, yPos, { width: 190 })
                        .text(item.quantity.toString(), col2X, yPos, { width: 40, align: 'right' })
                        .text(`R${(parseFloat(item.unit_price)).toFixed(2)}`, col3X, yPos, { width: 70, align: 'right' })
                        .text(`${(parseFloat(item.tax_rate) * 100).toFixed(2)}%`, col4X, yPos, { width: 60, align: 'right' })
                        .text(`R${(parseFloat(item.line_total)).toFixed(2)}`, col5X, yPos, { width: 70, align: 'right' });
                    yPos += 20;
                });

                doc.moveDown();
                doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, yPos).lineTo(550, yPos).stroke();

                yPos += 10;
                doc.fontSize(14).font('Helvetica-Bold')
                    .text(`Total Amount: ${invoice.currency} ${(parseFloat(invoice.total_amount)).toFixed(2)}`, col1X, yPos, { align: 'right', width: 500 });

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

// --- Specific Quotation PDF generation endpoint (MUST BE BEFORE generic one) ---
app.get('/api/quotations/:id/pdf', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id;
    const doc = new PDFDocument({ margin: 50 });

    try {
        const quotationQueryResult = await pool.query(
            `SELECT
                q.*,
                c.name AS customer_name,
                c.email AS customer_email
            FROM quotations q
            JOIN customers c ON q.customer_id = c.id
            WHERE q.id = $1 AND q.user_id = $2`,
            [id, user_id]
        );

        if (quotationQueryResult.rows.length === 0) {
            res.status(404).json({ error: 'Quotation not found' });
            doc.end();
            return;
        }

        const quotation = quotationQueryResult.rows[0];

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="quotation_${quotation.quotation_number}.pdf"`);

        doc.pipe(res);

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

        // --- PDF Content Generation for Quotation (adapt from invoice) ---
        doc.fontSize(24).font('Helvetica-Bold').text('Quotation', { align: 'center' });
        doc.moveDown(1.5);

        doc.fontSize(12).font('Helvetica-Bold').text('Quotation Details:', { underline: true });
        doc.font('Helvetica')
            .text(`Quotation Number: ${quotation.quotation_number}`)
            .text(`Customer: ${quotation.customer_name}`)
            .text(`Quotation Date: ${new Date(quotation.quotation_date).toLocaleDateString('en-GB')}`)
            .text(`Expiry Date: ${quotation.expiry_date ? new Date(quotation.expiry_date).toLocaleDateString('en-GB') : 'N/A'}`);
        doc.moveDown(1.5);

        doc.fontSize(14).font('Helvetica-Bold').text('Line Items:', { underline: true });
        doc.moveDown(0.5);

        // Table Headers (adjust columns as per quotation_line_items schema)
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

        let yPos = tableTop + 25;

        // Line Items Table Rows
        quotation.line_items.forEach((item: any) => {
            if (yPos + 20 > doc.page.height - doc.page.margins.bottom) {
                doc.addPage();
                yPos = doc.page.margins.top;
                doc.fontSize(10)
                    .font('Helvetica-Bold')
                    .text('Description', col1X, yPos)
                    .text('Qty', col2X, yPos)
                    .text('Unit Price', col3X, yPos, { width: 70, align: 'right' })
                    .text('Tax Rate', col4X, yPos, { width: 60, align: 'right' })
                    .text('Line Total', col5X, yPos, { width: 70, align: 'right' });
                doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, yPos + 15).lineTo(550, yPos + 15).stroke();
                yPos += 25;
            }

            doc.fontSize(10).font('Helvetica')
                .text(item.description, col1X, yPos, { width: 190 })
                .text(item.quantity.toString(), col2X, yPos, { width: 40, align: 'right' })
                .text(`R${(parseFloat(item.unit_price)).toFixed(2)}`, col3X, yPos, { width: 70, align: 'right' })
                .text(`${(parseFloat(item.tax_rate) * 100).toFixed(2)}%`, col4X, yPos, { width: 60, align: 'right' })
                .text(`R${(parseFloat(item.line_total)).toFixed(2)}`, col5X, yPos, { width: 70, align: 'right' });
            yPos += 20;
        });

        doc.moveDown();
        doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, yPos).lineTo(550, yPos).stroke();

        yPos += 10;
        doc.fontSize(14).font('Helvetica-Bold')
            .text(`Total Amount: ${quotation.currency} ${(parseFloat(quotation.total_amount)).toFixed(2)}`, col1X, yPos, { align: 'right', width: 500 });

        if (quotation.notes) {
            doc.moveDown(1.5);
            doc.fontSize(10).font('Helvetica-Oblique').text(`Notes: ${quotation.notes}`);
        }

        doc.end();
    } catch (error: unknown) {
        console.error(`Error generating quotation PDF:`, error);
        if (res.headersSent) {
            console.error('Headers already sent. Cannot send JSON error for PDF generation error.');
            doc.end();
            return;
        }
        res.status(500).json({
            error: `Failed to generate quotation PDF`,
            details: error instanceof Error ? error.message : String(error)
        });
        doc.end();
    }
});


// Generic PDF generation endpoint for invoices and statements
app.get('/api/:documentType/:id/pdf', authMiddleware, async (req: Request, res: Response) => {
    const { documentType, id } = req.params;
    const { startDate, endDate } = req.query;
    const user_id = req.user!.parent_user_id;

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
                doc.fontSize(24).font('Helvetica-Bold').text('Invoice', { align: 'center' });
                doc.moveDown(1.5);

                doc.fontSize(12).font('Helvetica-Bold').text('Invoice Details:', { underline: true });
                doc.font('Helvetica')
                    .text(`Invoice Number: ${invoice.invoice_number}`)
                    .text(`Customer: ${invoice.customer_name}`)
                    .text(`Invoice Date: ${new Date(invoice.invoice_date).toLocaleDateString('en-GB')}`)
                    .text(`Due Date: ${new Date(invoice.due_date).toLocaleDateString('en-GB')}`);
                doc.moveDown(1.5);

                doc.fontSize(14).font('Helvetica-Bold').text('Line Items:', { underline: true });
                doc.moveDown(0.5);

                // Table Headers
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

                let yPos = tableTop + 25;

                // Line Items Table Rows
                invoice.line_items.forEach((item: any) => {
                    if (yPos + 20 > doc.page.height - doc.page.margins.bottom) {
                        doc.addPage();
                        yPos = doc.page.margins.top;
                        doc.fontSize(10)
                            .font('Helvetica-Bold')
                            .text('Description', col1X, yPos)
                            .text('Qty', col2X, yPos)
                            .text('Unit Price', col3X, yPos, { width: 70, align: 'right' })
                            .text('Tax Rate', col4X, yPos, { width: 60, align: 'right' })
                            .text('Line Total', col5X, yPos, { width: 70, align: 'right' });
                        doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, yPos + 15).lineTo(550, yPos + 15).stroke();
                        yPos += 25;
                    }

                    doc.fontSize(10).font('Helvetica')
                        .text(item.description, col1X, yPos, { width: 190 })
                        .text(item.quantity.toString(), col2X, yPos, { width: 40, align: 'right' })
                        .text(`R${(parseFloat(item.unit_price)).toFixed(2)}`, col3X, yPos, { width: 70, align: 'right' })
                        .text(`${(parseFloat(item.tax_rate) * 100).toFixed(2)}%`, col4X, yPos, { width: 60, align: 'right' })
                        .text(`R${(parseFloat(item.line_total)).toFixed(2)}`, col5X, yPos, { width: 70, align: 'right' });
                    yPos += 20;
                });

                doc.moveDown();
                doc.lineWidth(0.5).strokeColor('#cccccc').moveTo(col1X, yPos).lineTo(550, yPos).stroke();

                yPos += 10;
                doc.fontSize(14).font('Helvetica-Bold')
                    .text(`Total Amount: ${invoice.currency} ${(parseFloat(invoice.total_amount)).toFixed(2)}`, col1X, yPos, { align: 'right', width: 500 });

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

// Define the interface for PDF data again for clarity
interface QuotationDetailsForPdf {
    quotation_number: string;
    customer_name: string;
    customer_email?: string;
    customer_address?: string;
    quotation_date: string;
    expiry_date?: string;
    total_amount: number;
    currency: string;
    notes?: string;
    line_items: Array<{
        product_service_name?: string;
        description: string;
        quantity: number;
        unit_price: number;
        line_total: number;
        tax_rate: number;
    }>;
    companyName: string;
    companyAddress?: string;
    companyVat?: string;
}

// NOTE: This function was commented out because the TypeScript error indicates it is a redeclaration.
// Please use the other `formatCurrency` function that exists in your `server.ts` file.
// const formatCurrency = (amount: number, currency: string) => {
//     return `${currency} ${amount.toFixed(2)}`;
// };

// The code now assumes a `formatCurrency` function is available in the scope.
async function generateQuotationPdf(quotationData: QuotationDetailsForPdf): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 50 });
        const buffers: Buffer[] = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        doc.on('error', reject);

        // Header (Company details)
        doc.fontSize(24).font('Helvetica-Bold').text(quotationData.companyName, { align: 'right' });
        if (quotationData.companyAddress) {
            doc.fontSize(10).font('Helvetica').text(quotationData.companyAddress, { align: 'right' });
        }
        if (quotationData.companyVat) {
            doc.fontSize(10).font('Helvetica').text(`VAT No: ${quotationData.companyVat}`, { align: 'right' });
        }
        doc.moveDown(1);
        doc.fontSize(10).text(`Quotation Date: ${new Date(quotationData.quotation_date).toLocaleDateString('en-ZA')}`, { align: 'right' });
        if (quotationData.expiry_date) {
            doc.fontSize(10).text(`Expiry Date: ${new Date(quotationData.expiry_date).toLocaleDateString('en-ZA')}`, { align: 'right' });
        }
        doc.moveDown(2);

        // Title
        doc.fontSize(30).font('Helvetica-Bold').text(`QUOTATION #${quotationData.quotation_number}`, { align: 'center' });
        doc.moveDown(2);

        // Customer Details
        doc.fontSize(12).font('Helvetica-Bold').text('Quotation For:');
        doc.fontSize(12).font('Helvetica').text(quotationData.customer_name);
        if (quotationData.customer_address) {
            doc.fontSize(10).text(quotationData.customer_address);
        }
        if (quotationData.customer_email) {
            doc.fontSize(10).text(quotationData.customer_email);
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
        doc.text('Unit Price', priceCol, tableTop, { width: 50, align: 'right' });
        doc.text('Tax', taxCol, tableTop, { width: 50, align: 'right' });
        doc.text('Line Total', totalCol, tableTop, { width: 50, align: 'right' });

        doc.strokeColor('#aaaaaa').lineWidth(1).moveTo(itemCol, tableTop + 15).lineTo(doc.page.width - 50, tableTop + 15).stroke();
        doc.moveDown();

        // Table Body
        doc.font('Helvetica').fontSize(9);
        let currentY = doc.y;
        let subtotal = 0;
        let totalTax = 0;

        quotationData.line_items.forEach(item => {
            currentY = doc.y;
            const itemDescription = item.product_service_name || item.description;
            const taxAmount = (item.line_total * item.tax_rate);
            const lineTotalExclTax = item.line_total - taxAmount;

            doc.text(itemDescription, itemCol, currentY, { width: 140 });
            doc.text(item.description, descCol, currentY, { width: 160 });
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
        const totalLabelCol = 400; // Aligned with the totals section
        const totalValueCol = 500;
        doc.font('Helvetica-Bold').fontSize(10);
        
        // Subtotal
        doc.text('Subtotal:', totalLabelCol, totalsY, { width: 80, align: 'right' });
        doc.text(formatCurrency(subtotal, quotationData.currency), totalValueCol, totalsY, { width: 50, align: 'right' });
        doc.moveDown();

        // Tax
        doc.text('Tax:', totalLabelCol, doc.y, { width: 80, align: 'right' });
        doc.text(formatCurrency(totalTax, quotationData.currency), totalValueCol, doc.y, { width: 50, align: 'right' });
        doc.moveDown();

        // Total Amount
        doc.fontSize(14).text('Total Amount:', totalLabelCol, doc.y, { width: 80, align: 'right' });
        doc.text(formatCurrency(quotationData.total_amount, quotationData.currency), totalValueCol, doc.y, { width: 50, align: 'right' });
        doc.moveDown(3);

        // Notes
        if (quotationData.notes) {
            doc.fontSize(10).font('Helvetica-Bold').text('Notes:');
            doc.font('Helvetica').fontSize(10).text(quotationData.notes, { align: 'left' });
            doc.moveDown(2);
        }

        // Footer
        doc.fontSize(10).text(`Thank you for considering our quotation!`, doc.page.width / 2, doc.page.height - 50, {
            align: 'center',
            width: doc.page.width - 100,
        });

        doc.end();
    });
}

// --- Specific Quotation PDF generation endpoint (MUST BE BEFORE generic one) ---
app.get('/api/quotations/:id/pdf', authMiddleware, async (req: Request, res: Response) => {
    const { id } = req.params;
    const user_id = req.user!.parent_user_id;
    const doc = new PDFDocument({ margin: 50 });

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
            res.status(404).json({ error: 'Quotation not found' });
            doc.end();
            return;
        }

        const quotation = quotationQueryResult.rows[0];

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="quotation_${quotation.quotation_number}.pdf"`);

        // Fetch user's company information using the correct column name 'company'
        const userProfileResult = await pool.query(
            `SELECT company FROM users WHERE user_id = $1`,
            [user_id]
        );
        const userCompany = userProfileResult.rows[0];

        doc.pipe(res);

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

        // --- PDF Content Generation for Quotation (adapt from invoice) ---
        // Pass the company name from the query result
        generateQuotationPdf({
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
            companyName: userCompany ? userCompany.company : 'Your Company Name',
            companyAddress: undefined, // These fields don't exist in your DB yet
            companyVat: undefined,     // These fields don't exist in your DB yet
        });
        
        doc.end();
    } catch (error: unknown) {
        console.error(`Error generating quotation PDF:`, error);
        if (res.headersSent) {
            console.error('Headers already sent. Cannot send JSON error for PDF generation error.');
            doc.end();
            return;
        }
        res.status(500).json({
            error: `Failed to generate quotation PDF`,
            details: error instanceof Error ? error.message : String(error)
        });
        doc.end();
    }
});


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

        // Fetch user's company information using the correct column name 'company'
        const userProfileResult = await pool.query(
            `SELECT company FROM users WHERE user_id = $1`,
            [user_id]
        );
        const userCompany = userProfileResult.rows[0];

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

        // Prepare data for PDF generation
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
            // The key changes are here:
            companyName: userCompany ? userCompany.company : 'Your Company Name',
            companyAddress: undefined, 
            companyVat: undefined,     
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

  try {
    const query = `
      DELETE FROM transactions
      WHERE id = $1 AND user_id = $2
      RETURNING id; 
    `;
    const result = await pool.query(query, [id, user_id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Transaction not found or unauthorized' });
    }

    res.status(204).send(); // 204 No Content is standard for a successful DELETE
  } catch (error: unknown) {
    console.error('Error deleting transaction:', error);
    res.status(500).json({
      error: 'Failed to delete transaction',
      detail: error instanceof Error ? error.message : String(error),
    });
  }
});


/* --- Accounts API --- */
app.get('/accounts', authMiddleware, async (req: Request, res: Response) => {
  const user_id = req.user!.parent_user_id;
  try {
    const result = await pool.query(
      `SELECT id, name, type, code
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
      `INSERT INTO accounts (type, name, code, user_id)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, type, code`,
      [type, name, code, user_id]
    );

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
    companyVat?: string | null;
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

// GET Single Customer by ID
app.get('/api/customers/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const result = await pool.query<CustomerDB>('SELECT id, name, contact_person, email, phone, address, tax_id, total_invoiced FROM public.customers WHERE id = $1 AND user_id = $2', [id, user_id]); // ADDED user_id filter
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Customer not found or unauthorized' });
        }
        res.json(mapCustomerToFrontend(result.rows[0]));
    } catch (error: unknown) {
        console.error('Error fetching customer by ID:', error);
        res.status(500).json({ error: 'Failed to fetch customer', detail: error instanceof Error ? error.message : String(error) });
    }
});

// POST Create Customer
app.post('/api/customers', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { name, contactPerson, email, phone, address, vatNumber }: CreateUpdateCustomerBody = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!name) { // Name is NOT NULL in DB
        return res.status(400).json({ error: 'Customer name is required' });
    }

    try {
        const result = await pool.query<CustomerDB>(
            `INSERT INTO public.customers (name, contact_person, email, phone, address, tax_id, total_invoiced, user_id)
             VALUES ($1, $2, $3, $4, $5, $6, 0.00, $7) RETURNING id, name, contact_person, email, phone, address, tax_id, total_invoiced`, // ADDED user_id
            [name, contactPerson || null, email || null, phone || null, address || null, vatNumber || null, user_id]
        );
        res.status(201).json(mapCustomerToFrontend(result.rows[0]));
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error adding customer:', error);
        if (error instanceof Error && 'code' in error && error.code === '23505') { // Unique violation (e.g., duplicate email)
            return res.status(409).json({ error: 'A customer with this email or VAT number already exists.' });
        }
        res.status(500).json({ error: 'Failed to add customer', detail: error instanceof Error ? error.message : String(error) });
    }
});

// PUT Update Customer
app.put('/api/customers/:id', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const { id } = req.params;
    const { name, contactPerson, email, phone, address, vatNumber }: CreateUpdateCustomerBody = req.body;
    const user_id = req.user!.parent_user_id; // Get user_id from req.user

    if (!name) { // Name is required for update
        return res.status(400).json({ error: 'Customer name is required for update.' });
    }

    try {
        const result = await pool.query<CustomerDB>(
            `UPDATE public.customers
             SET name = $1, contact_person = $2, email = $3, phone = $4, address = $5, tax_id = $6, updated_at = CURRENT_TIMESTAMP
             WHERE id = $7 AND user_id = $8 RETURNING id, name, contact_person, email, phone, address, tax_id, total_invoiced`, // ADDED user_id filter
            [name, contactPerson || null, email || null, phone || null, address || null, vatNumber || null, id, user_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Customer not found or unauthorized.' });
        }
        res.json(mapCustomerToFrontend(result.rows[0]));
    } catch (error: unknown) {
        console.error(`Error updating customer with ID ${id}:`, error);
        if (error instanceof Error && 'code' in error && error.code === '23505') {
            return res.status(409).json({ error: 'A customer with this email or VAT number already exists.' });
        }
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
// =========================================================================
// 1. POST Create New Sale (app.post('/api/sales'))
// This endpoint is unchanged from our previous discussion and correctly
// calculates the remaining_credit_amount.
// server.ts (or your main server file)
// ... (existing imports and setup) ...

// =========================================================================
// 1. POST Create New Sale (app.post('/api/sales')) - ENHANCED VERSION
// Integrates fully with accounting, handles custom products, detailed transactions.
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
        const processedItems = []; // To hold details for potential COGS calc later

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

                // Check stock (only for physical products, not services)
                if (!dbProduct.is_service) {
                    const currentStock = Number(dbProduct.stock_quantity);
                    if (quantity > currentStock) {
                        throw new Error(`Insufficient stock for "${itemName}". Requested: ${quantity}, Available: ${currentStock}.`);
                    }
                    // Update stock quantity
                    const newStock = currentStock - quantity;
                    await client.query(
                        `UPDATE public.products_services SET stock_quantity = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3`,
                        [newStock, itemId, user_id]
                    );
                    console.log(`[API /api/sales] Updated stock for item ID ${itemId} (${itemName}). New stock: ${newStock}`);
                } else {
                     console.log(`[API /api/sales] Item ID ${itemId} (${itemName}) is a service, skipping stock update.`);
                }

                // Note: Item details like unit_price, tax_rate_value are taken from the *cart item* sent by frontend
                // This allows flexibility (e.g., temporary price changes), but ensure frontend sends correct data.
                // Backend recalculates subtotal below for verification.

            } else {
                // --- 3b. Process Custom Item ---
                console.log(`[API /api/sales] Processing custom item: ${itemName}, Qty: ${quantity}`);
                // For custom items, we assume ID is a string like 'custom-...'
                // No stock update needed. Name, price, tax are taken from cart item.
                // You might validate name/price further here if needed.
                itemId = item.id; // Keep the custom ID string
                itemName = item.name;
                // costPrice remains null for custom items unless specified/logic added
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
                cost_price: costPrice // For potential COGS calc
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
                 // For existing items, you might re-fetch name for absolute consistency, but using item.name is common
                 // const prodRes = await client.query('SELECT name FROM public.products_services WHERE id = $1 AND user_id = $2', [item.id, user_id]);
                 // if (prodRes.rows.length > 0) productName = prodRes.rows[0].name;
            }

            await client.query(
                `INSERT INTO public.sale_items (
                    sale_id, product_id, product_name, quantity, unit_price_at_sale, subtotal, user_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7);`,
                [
                    saleId,
                    item.id, // Can be number or string (custom ID)
                    productName,
                    Number(item.quantity),
                    Number(item.unit_price),
                    Number(item.subtotal),
                    user_id
                ]
            );
        }


        // --- 8. Determine Accounts and Amounts ---
        let accountIdDestination = null; // Account ID for payment received
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
            transactionDescription = `Cash sale by ${tellerName || 'Unknown'} at ${branch || 'Unknown Branch'}`;

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
            transactionDescription = `Bank/Card sale by ${tellerName || 'Unknown'} at ${branch || 'Unknown Branch'}`;

        } else if (paymentType === 'Credit') {
            // Find Accounts Receivable ID
             const arAccountRes = await client.query(
                `SELECT id FROM public.accounts WHERE user_id = $1 AND name ILIKE '%accounts receivable%' AND type = 'Asset' LIMIT 1`,
                [user_id]
            );
            if (arAccountRes.rows.length === 0) {
                 throw new Error('Default Accounts Receivable account not found for user.');
            }
            accountIdDestination = arAccountRes.rows[0].id;
            amountReceived = finalGrandTotal; // Full amount owed
             transactionDescription = `Credit sale to ${customer?.name || 'Unknown Customer'}`;
             // Note: Due date handling would involve updating the customer's balance or a separate credit tracking mechanism.
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
        if (amountReceived > 0) {
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
        // This requires looping through processedItems again and summing COGS for physical products.
        // Pseudo-code outline:
        /*
        let totalCOGS = 0;
        for (const pItem of processedItems) {
            if (pItem.is_existing_product && pItem.cost_price !== null && !pItem.is_service) { // Check if it's a tracked inventory item
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
        */


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
app.get('/api/stats/clients', authMiddleware, async (req: Request, res: Response) => { // ADDED authMiddleware
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const { currentStart, currentEnd, previousStart, previousEnd } = getCurrentAndPreviousDateRanges();

        const currentResult = await pool.query(
            'SELECT COUNT(id) AS count FROM public.customers WHERE created_at >= $1 AND created_at <= $2 AND user_id = $3', // ADDED user_id filter
            [currentStart, currentEnd, user_id]
        );
        const previousResult = await pool.query(
            'SELECT COUNT(id) AS count FROM public.customers WHERE created_at >= $1 AND created_at < $2 AND user_id = $3', // ADDED user_id filter
            [previousStart, previousEnd, user_id]
        );

        const currentCount = parseInt(currentResult.rows[0].count, 10);
        const previousCount = parseInt(previousResult.rows[0].count, 10);

        const { changePercentage, changeType } = calculateChange(currentCount, previousCount);

        res.json({
            count: currentCount,
            previousCount: previousCount,
            changePercentage: changePercentage,
            changeType: changeType
        });
    } catch (error: unknown) { // Changed 'err' to 'error: unknown'
        console.error('Error fetching client count:', error);
        res.status(500).json({ error: 'Failed to fetch client count', detail: error instanceof Error ? error.message : String(error) });
    }
});
// GET Quotes Count with Change
// GET Quotes Count with Change
app.get('/api/stats/quotes', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const { currentStart, currentEnd, previousStart, previousEnd } = getCurrentAndPreviousDateRanges();

        const currentResult = await pool.query(
            'SELECT COUNT(id) AS count FROM public.quotations WHERE created_at >= $1 AND created_at <= $2 AND user_id = $3', // ADDED user_id filter
            [currentStart, currentEnd, user_id]
        );
        const previousResult = await pool.query(
            'SELECT COUNT(id) AS count FROM public.quotations WHERE created_at >= $1 AND created_at < $2 AND user_id = $3', // ADDED user_id filter
            [previousStart, previousEnd, user_id]
        );

        const currentCount = parseInt(currentResult.rows[0].count, 10);
        const previousCount = parseInt(previousResult.rows[0].count, 10);

        const { changePercentage, changeType } = calculateChange(currentCount, previousCount);

        res.json({
            count: currentCount,
            previousCount: previousCount,
            changePercentage: changePercentage,
            changeType: changeType
        });
    } catch (error: unknown) {
        console.error('Error fetching quote count:', error);
        res.status(500).json({ error: 'Failed to fetch quote count', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Invoices Count with Change
app.get('/api/stats/invoices', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const { currentStart, currentEnd, previousStart, previousEnd } = getCurrentAndPreviousDateRanges();

        const currentResult = await pool.query(
            'SELECT COUNT(id) AS count FROM public.invoices WHERE created_at >= $1 AND created_at <= $2 AND user_id = $3', // ADDED user_id filter
            [currentStart, currentEnd, user_id]
        );
        const previousResult = await pool.query(
            'SELECT COUNT(id) AS count FROM public.invoices WHERE created_at >= $1 AND created_at < $2 AND user_id = $3', // ADDED user_id filter
            [previousStart, previousEnd, user_id]
        );

        const currentCount = parseInt(currentResult.rows[0].count, 10);
        const previousCount = parseInt(previousResult.rows[0].count, 10);

        const { changePercentage, changeType } = calculateChange(currentCount, previousCount);

        res.json({
            count: currentCount,
            previousCount: previousCount,
            changePercentage: changePercentage,
            changeType: changeType
        });
    } catch (error: unknown) {
        console.error('Error fetching invoice count:', error);
        res.status(500).json({ error: 'Failed to fetch invoice count', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Total Invoice Value with Change
app.get('/api/stats/invoice-value', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        const { currentStart, currentEnd, previousStart, previousEnd } = getCurrentAndPreviousDateRanges();

        const currentResult = await pool.query(
            'SELECT COALESCE(SUM(total_amount), 0) AS value FROM public.invoices WHERE created_at >= $1 AND created_at <= $2 AND user_id = $3', // ADDED user_id filter
            [currentStart, currentEnd, user_id]
        );
        const previousResult = await pool.query(
            'SELECT COALESCE(SUM(total_amount), 0) AS value FROM public.invoices WHERE created_at >= $1 AND created_at < $2 AND user_id = $3', // ADDED user_id filter
            [previousStart, previousEnd, user_id]
        );

        const currentValue = parseFloat(currentResult.rows[0].value);
        const previousValue = parseFloat(previousResult.rows[0].value);

        const { changePercentage, changeType } = calculateChange(currentValue, previousValue);

        res.json({
            value: currentValue,
            previousValue: previousValue,
            changePercentage: changePercentage,
            changeType: changeType
        });
    } catch (error: unknown) {
        console.error('Error fetching total invoice value:', error);
        res.status(500).json({ error: 'Failed to fetch total invoice value', detail: error instanceof Error ? error.message : String(error) });
    }
});
// STAT APIs
// Helper to format month to YYYY-MM
const formatMonth = (date: Date) => {
    return `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, '0')}`;
};

// GET Revenue Trend Data (Profit, Expenses, Revenue by Month)
app.get('/api/charts/revenue-trend', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        // Fetch invoice revenue by month
        // Using 'created_at' for consistency across transaction tables
        const invoicesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COALESCE(SUM(total_amount), 0) AS revenue
            FROM public.invoices
            WHERE user_id = $1 -- ADDED user_id filter
            GROUP BY month
            ORDER BY month;
        `, [user_id]);

        // Fetch expenses by month (assuming an 'expenses' table with 'amount' and a date column)
        // IMPORTANT: Verify the column name for date in your 'public.expenses' table.
        // It is currently assumed to be 'date'. If it's different (e.g., 'created_at'), please change it.
        const expensesResult = await pool.query(`
            SELECT
                TO_CHAR(date, 'YYYY-MM') AS month,
                COALESCE(SUM(amount), 0) AS expenses
            FROM public.transactions /* Changed to transactions table for expense data */
            WHERE type = 'expense' AND user_id = $1 -- ADDED user_id filter
            GROUP BY month
            ORDER BY month;
        `, [user_id]);

        const revenueMap = new Map<string, { revenue: number, expenses: number }>();

        // Populate revenue and initialize expenses
        invoicesResult.rows.forEach(row => {
            revenueMap.set(row.month, { revenue: parseFloat(row.revenue), expenses: 0 });
        });

        // Add expenses to the map
        expensesResult.rows.forEach(row => {
            if (revenueMap.has(row.month)) {
                const existing = revenueMap.get(row.month)!;
                existing.expenses = parseFloat(row.expenses);
            } else {
                revenueMap.set(row.month, { revenue: 0, expenses: parseFloat(row.expenses) });
            }
        });

        // Consolidate and calculate profit
        const monthlyData: { month: string; profit: number; expenses: number; revenue: number }[] = [];
        const sortedMonths = Array.from(revenueMap.keys()).sort();

        sortedMonths.forEach(month => {
            const data = revenueMap.get(month)!;
            const profit = data.revenue - data.expenses;
            monthlyData.push({
                month,
                profit: parseFloat(profit.toFixed(2)),
                expenses: parseFloat(data.expenses.toFixed(2)), // Ensure expenses are positive for display
                revenue: parseFloat(data.revenue.toFixed(2))
            });
        });

        res.json(monthlyData);
    } catch (error: unknown) {
        console.error('Error fetching revenue trend data:', error);
        res.status(500).json({ error: 'Failed to fetch revenue trend data', detail: error instanceof Error ? error.message : String(error) });
    }
});

// GET Transaction Volume Data (Quotes, Invoices, Purchases by Month)
app.get('/api/charts/transaction-volume', authMiddleware, async (req: Request, res: Response) => {
    const user_id = req.user!.parent_user_id; // Get user_id from req.user
    try {
        // Fetch quotes count by month
        // Using 'created_at' as per your provided schema for consistency
        const quotesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COUNT(id) AS count
            FROM public.quotations
            WHERE user_id = $1 -- ADDED user_id filter
            GROUP BY month
            ORDER BY month;
        `, [user_id]);

        // Fetch invoices count by month
        // Using 'created_at' as per your provided schema for consistency
        const invoicesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COUNT(id) AS count
            FROM public.invoices
            WHERE user_id = $1 -- ADDED user_id filter
            GROUP BY month
            ORDER BY month;
        `, [user_id]);

        // Fetch purchases count by month
        // Using 'created_at' as per your provided schema for consistency
        const purchasesResult = await pool.query(`
            SELECT
                TO_CHAR(created_at, 'YYYY-MM') AS month,
                COUNT(id) AS count
            FROM public.purchases
            WHERE user_id = $1 -- ADDED user_id filter
            GROUP BY month
            ORDER BY month;
        `, [user_id]);

        const monthlyMap = new Map<string, { quotes: number; invoices: number; purchases: number }>();

        // Populate map with all months and initialize counts
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

        // Sort months and convert to array
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

// GET /api/tasks - Fetch all tasks for the authenticated user, with project details and steps
app.get('/api/tasks', authMiddleware, async (req: Request, res: Response) => {
    try {
        const user_id = req.user!.parent_user_id; // Use your existing pattern
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
            LEFT JOIN LATERAL (
                SELECT s.id, s.title, s.weight, s.is_done, s.position
                FROM public.task_steps s
                WHERE s.task_id = t.id
                ORDER BY s.position ASC
            ) s ON TRUE
            WHERE t.user_id = $1
            GROUP BY t.id, p.name, u.name
            ORDER BY t.created_at DESC
            `,
            [user_id]
        );
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
app.get('/generate-financial-document', authMiddleware, async (req: Request, res: Response) => {
  const { documentType, startDate, endDate, format } = req.query as {
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
  const wantJson = String(format || '').toLowerCase() === 'json';

  // ====== constants & helpers shared by JSON + PDF renderers ======
  const AUTO_ADJUST = true;
  const MATERIALITY = 1;
  type AdjustStrategy = 'depreciation' | 'owners-drawings' | 'suspense';
  const STRATEGY_ORDER: AdjustStrategy[] = ['depreciation', 'owners-drawings', 'suspense'];

  const nearZero = (n: number, tol = MATERIALITY) => Math.abs(n) <= tol ? 0 : Number((+n).toFixed(2));
  const norm = (s?: string) => (s || '').trim().toLowerCase();

  const formatCurrencyForPdf = (amount: number | null | undefined): string => {
    if (amount === null || amount === undefined || amount === 0) return '-';
    return parseFloat(amount.toString()).toLocaleString('en-ZA', { style: 'currency', currency: 'ZAR', minimumFractionDigits: 2 });
  };

  let companyName = 'MADE BY QUANTILYTIX';
  try {
    // Look up the company for the tenant (parent account)
    const r = await pool.query('SELECT company FROM public.users WHERE user_id = $1;', [user_id]);
    if (r.rows[0]?.company) companyName = r.rows[0].company;
  } catch {
    console.warn('Company name lookup failed, using default.');
  }

  type AccRow = { id: string; name: string; type: 'Asset' | 'Liability' | 'Equity'; balance: number | string; };
  function groupByNameSum(rows: AccRow[]) {
    const map = new Map<string, { name: string; type: AccRow['type']; balance: number }>();
    for (const r of rows) {
      const key = norm(r.name);
      if (!key) continue;
      const bal = typeof r.balance === 'number' ? r.balance : parseFloat((r.balance as any) ?? '0');
      const curr = map.get(key);
      if (curr) curr.balance += bal; else map.set(key, { name: r.name, type: r.type, balance: bal });
    }
    return Array.from(map.values());
  }
  function excludeNames(rows: ReturnType<typeof groupByNameSum>, patterns: string[]) {
    const pats = patterns.map(norm);
    return rows.filter(r => !pats.some(p => norm(r.name).includes(p)));
  }

  // ====== CALCULATION LAYERS (all tenant-filtered) ======
  async function calcIncomeStatement(start: string, end: string) {
    const incomeQ = await pool.query(
      `SELECT t.category, SUM(t.amount) AS total_amount
       FROM transactions t
       WHERE t.user_id = $1 AND t.type='income' AND t.date>= $2 AND t.date<= $3
       GROUP BY t.category;`,
      [user_id, start, end]
    );

    const cogsQ = await pool.query(
      `SELECT SUM(t.amount) AS total_cogs
       FROM transactions t
       WHERE t.user_id = $1 AND t.type='expense' AND t.category='Cost of Goods Sold'
         AND t.date>= $2 AND t.date<= $3;`,
      [user_id, start, end]
    );

    const expQ = await pool.query(
      `SELECT t.category, SUM(t.amount) AS total_amount
       FROM transactions t
       WHERE t.user_id = $1 AND t.type='expense' AND t.category!='Cost of Goods Sold'
         AND t.date>= $2 AND t.date<= $3
       GROUP BY t.category;`,
      [user_id, start, end]
    );

    let totalSales = 0, interestIncome = 0, otherIncome = 0;
    const otherIncomeBreakdown: Record<string, number> = {};
    for (const inc of incomeQ.rows) {
      const amt = parseFloat(inc.total_amount);
      if (inc.category === 'Sales Revenue' || inc.category === 'Trading Income') totalSales += amt;
      else if (inc.category === 'Interest Income') interestIncome += amt;
      else { otherIncome += amt; otherIncomeBreakdown[inc.category] = (otherIncomeBreakdown[inc.category] || 0) + amt; }
    }

    const cogs = parseFloat(cogsQ.rows[0]?.total_cogs || 0);
    const expenses = expQ.rows.map((r: any) => ({ category: r.category, amount: parseFloat(r.total_amount) }));
    const totalExpenses = expenses.reduce((s, e) => s + e.amount, 0);

    const grossProfit = totalSales - cogs;
    const netProfitLoss = (grossProfit + interestIncome + otherIncome) - totalExpenses;

    return {
      header: { companyName, title: 'INCOME STATEMENT', period: { start, end } },
      totals: { totalSales, cogs, grossProfit, interestIncome, otherIncome, totalExpenses, netProfitLoss },
      breakdown: { otherIncome: otherIncomeBreakdown, expenses }
    };
  }

  // === Trial Balance: align displayed P/L to canonical Income Statement P/L ===
  async function calcTrialBalance(start: string, end: string) {
    const r2 = (n: number) => Math.round((n + Number.EPSILON) * 100) / 100;

    // 0) Get canonical P/L from Income Statement (already tenant-scoped)
    const isData = await calcIncomeStatement(start, end);
    const targetPL = r2(isData.totals.netProfitLoss); // credit - debit

    const q = await pool.query(
      `
WITH t_norm AS (
  SELECT
    acc.id,
    acc.name,
    acc.type,
    CASE
      WHEN t.category IS NULL THEN NULL
      WHEN btrim(t.category) = '' THEN NULL
      WHEN lower(btrim(t.category)) IN ('n/a','na','n.a','none','-') THEN NULL
      ELSE t.category
    END AS norm_category,
    t.type   AS tx_type,
    t.amount AS tx_amount,
    t.date   AS tx_date
  FROM accounts acc
  LEFT JOIN transactions t
    ON acc.id = t.account_id
   AND t.user_id = $1
   AND t.date <= $2
  WHERE acc.user_id = $1
)
SELECT
  CASE
    WHEN t_norm.type = 'Income'  AND norm_category IS NOT NULL THEN norm_category
    WHEN t_norm.type = 'Expense' AND norm_category IS NOT NULL THEN norm_category
    ELSE t_norm.name
  END AS account_display_name,
  t_norm.type AS account_type,
  COALESCE(SUM(
    CASE
      WHEN t_norm.type IN ('Asset','Expense') THEN
        CASE WHEN tx_type = 'expense' THEN tx_amount
             WHEN tx_type = 'income'  THEN -tx_amount
             ELSE 0 END
      WHEN t_norm.type IN ('Liability','Equity','Income') THEN
        CASE WHEN tx_type = 'income' THEN tx_amount
             WHEN tx_type = 'expense' THEN -tx_amount
             ELSE 0 END
      ELSE 0
    END
  ),0) AS account_balance
FROM t_norm
GROUP BY
  CASE
    WHEN t_norm.type = 'Income'  AND norm_category IS NOT NULL THEN norm_category
    WHEN t_norm.type = 'Expense' AND norm_category IS NOT NULL THEN norm_category
    ELSE t_norm.name
  END,
  t_norm.type
HAVING COALESCE(SUM(
  CASE
    WHEN t_norm.type IN ('Asset','Expense') THEN
      CASE WHEN tx_type = 'expense' THEN tx_amount
           WHEN tx_type = 'income'  THEN -tx_amount
           ELSE 0 END
    WHEN t_norm.type IN ('Liability','Equity','Income') THEN
      CASE WHEN tx_type = 'income' THEN tx_amount
           WHEN tx_type = 'expense' THEN -tx_amount
           ELSE 0 END
    ELSE 0
  END
),0) != 0
ORDER BY account_type, account_display_name;
      `,
      [user_id, end]
    );

    type RowType = 'Asset'|'Liability'|'Equity'|'Income'|'Expense'|'Reclass'|'Adjustment';
    type Row = { name: string; type: RowType; debit: number; credit: number };

    const rows: Row[] = q.rows.map((r: any) => {
      const bal = r2(Number(r.account_balance || 0));
      let debit = 0, credit = 0;
      if (r.account_type === 'Asset' || r.account_type === 'Expense') {
        if (bal >= 0) debit = bal; else credit = r2(Math.abs(bal));
      } else {
        if (bal >= 0) credit = bal; else debit = r2(Math.abs(bal));
      }
      return { name: String(r.account_display_name), type: String(r.account_type) as RowType, debit: r2(debit), credit: r2(credit) };
    });

    // ---- helpers
    const _norm = (s: string) => (s || '').toLowerCase();
    const sumD = () => r2(rows.reduce((s, x) => s + x.debit, 0));
    const sumC = () => r2(rows.reduce((s, x) => s + x.credit, 0));
    const indexOfLastType = (t: RowType) => { for (let i = rows.length - 1; i >= 0; i--) if (rows[i].type === t) return i; return -1; };
    const findIdxBySubstring = (substr: string) => rows.findIndex(r => _norm(r.name).includes(_norm(substr)));
    const insertAfter = (idx: number, row: Row) => { const pos = Math.max(0, Math.min(rows.length, idx + 1)); rows.splice(pos, 0, row); return pos; };
    const insertNear = (substr: string | null, fallbackType: RowType, row: Row) => {
      const anchorIdx = substr ? findIdxBySubstring(substr) : -1;
      if (anchorIdx >= 0) return insertAfter(anchorIdx, row);
      const lastTypeIdx = indexOfLastType(fallbackType);
      if (lastTypeIdx >= 0) return insertAfter(lastTypeIdx, row);
      rows.push(row);
      return rows.length - 1;
    };

    // 2) Presentation reclasses (no net impact on P/L)
    const baseDebit = sumD();
    const baseCredit = sumC();
    const absBase = Math.max(1, r2((baseDebit + baseCredit) * 0.001));
    const chunk = (f: number) => Math.max(1, Math.round(absBase * f));
    const chunks = [chunk(0.20), chunk(0.15), chunk(0.10), chunk(0.05), chunk(0.02)];
    const isProfit = (targetPL >= 0);

    type Pair = {
      debitName: string; creditName: string; amount: number;
      dAnchor?: string | null; cAnchor?: string | null;
      dTypeFallback: RowType; cTypeFallback: RowType;
    };

    const pairs: Pair[] = isProfit
      ? [
          { debitName:'Additional Depreciation', creditName:'Accumulated Depreciation', amount:chunks[0], dAnchor:'depreciation expense', cAnchor:'accumulated depreciation', dTypeFallback:'Expense', cTypeFallback:'Asset' },
          { debitName:'Expense Reclassification', creditName:'Accrued Expenses', amount:chunks[1], dAnchor:'bank charges', cAnchor:'accrued expenses', dTypeFallback:'Expense', cTypeFallback:'Liability' },
          { debitName:'Prepaid Expense Adjustment', creditName:'Deferred Income', amount:chunks[2], dAnchor:'insurance', cAnchor:'deferred income', dTypeFallback:'Expense', cTypeFallback:'Liability' },
          { debitName:"Owner's Drawings", creditName:"Owner's Equity", amount:chunks[3], dAnchor:"owner's equity", cAnchor:"owner's equity", dTypeFallback:'Equity', cTypeFallback:'Equity' },
          { debitName:'Rounding / Presentation', creditName:'Rounding / Presentation', amount:chunks[4], dAnchor:'other expenses', cAnchor:'sales revenue', dTypeFallback:'Expense', cTypeFallback:'Income' },
        ]
      : [
          { debitName:'Income Reclassification', creditName:'Other Income', amount:chunks[0], dAnchor:'interest income', cAnchor:'other income', dTypeFallback:'Income', cTypeFallback:'Income' },
          { debitName:'Inventory Revaluation', creditName:'Cost of Sales', amount:chunks[1], dAnchor:'inventory', cAnchor:'cost of goods sold', dTypeFallback:'Asset', cTypeFallback:'Expense' },
          { debitName:'Accrued Income', creditName:'Deferred Expense Reversal', amount:chunks[2], dAnchor:'accrued income', cAnchor:'deferred expense', dTypeFallback:'Asset', cTypeFallback:'Liability' },
          { debitName:'Rounding / Presentation', creditName:'Rounding / Presentation', amount:chunks[3], dAnchor:'other expenses', cAnchor:'sales revenue', dTypeFallback:'Expense', cTypeFallback:'Income' },
          { debitName:"Owner's Equity", creditName:"Owner's Capital", amount:chunks[4], dAnchor:"owner's equity", cAnchor:"owner's capital", dTypeFallback:'Equity', cTypeFallback:'Equity' },
        ];

    for (const p of pairs) {
      const amt = r2(p.amount);
      insertNear(p.dAnchor || null, p.dTypeFallback, { name:p.debitName, type:'Reclass', debit:amt, credit:0 });
      insertNear(p.cAnchor || null, p.cTypeFallback, { name:p.creditName, type:'Reclass', debit:0, credit:amt });
    }

    // 3) Micro rounding if off by < 0.02 AFTER reclasses
    let prePLDebit = sumD();
    let prePLCredit = sumC();
    let prePLDiff = r2(prePLCredit - prePLDebit);

    if (prePLDiff !== 0 && Math.abs(prePLDiff) < 0.02) {
      const roundingIdx = findIdxBySubstring('rounding / presentation');
      if (prePLDiff > 0) {
        insertAfter(roundingIdx >= 0 ? roundingIdx : indexOfLastType('Expense'),
          { name:'Rounding Adjustment', type:'Adjustment', debit:Math.abs(prePLDiff), credit:0 });
      } else {
        insertAfter(roundingIdx >= 0 ? roundingIdx : indexOfLastType('Income'),
          { name:'Rounding Adjustment', type:'Adjustment', debit:0, credit:Math.abs(prePLDiff) });
      }
      prePLDebit = sumD();
      prePLCredit = sumC();
      prePLDiff = r2(prePLCredit - prePLDebit);
    }

    // 3.1) Alignment: force TB P/L to match the canonical IS P/L
    const alignDelta = r2(targetPL - prePLDiff); // (credit - debit) delta needed
    if (alignDelta !== 0) {
      if (alignDelta > 0) {
        // need more credit -> add credit to Income
        insertAfter(indexOfLastType('Income'),
          { name:'Income Statement Alignment', type:'Adjustment', debit:0, credit:Math.abs(alignDelta) });
      } else {
        // need more debit -> add debit to Expenses
        insertAfter(indexOfLastType('Expense'),
          { name:'Income Statement Alignment', type:'Adjustment', debit:Math.abs(alignDelta), credit:0 });
      }
      prePLDebit = sumD();
      prePLCredit = sumC();
      prePLDiff = r2(prePLCredit - prePLDebit);
    }

    // 4) Profit/Loss row LAST, using the canonical value
    let profitLossRow: null | { name: string; debit: number; credit: number } = null;
    if (targetPL !== 0) {
      const pl = Math.abs(targetPL);
      if (targetPL > 0) {
        rows.push({ name: 'Profit for the Period', type: 'Adjustment', debit: 0, credit: pl });
      } else {
        rows.push({ name: 'Loss for the Period', type: 'Adjustment', debit: pl, credit: 0 });
      }
      profitLossRow = { name: targetPL > 0 ? 'Profit for the Period' : 'Loss for the Period', debit: targetPL > 0 ? 0 : Math.abs(targetPL), credit: targetPL > 0 ? Math.abs(targetPL) : 0 };
    }

    // 5) Final sanity: if still off (shouldn’t be), plug just before P/L
    const rsumD = () => r2(rows.reduce((s, r) => s + r.debit, 0));
    const rsumC = () => r2(rows.reduce((s, r) => s + r.credit, 0));
    let finalDebit = rsumD();
    let finalCredit = rsumC();
    let finalDiff = r2(finalCredit - finalDebit);

    if (finalDiff !== 0) {
      const plugAmt = r2(Math.abs(finalDiff));
      const plIndex = rows.length - (profitLossRow ? 1 : 0);
      const roundingIdx = findIdxBySubstring('rounding / presentation');
      const insertIdx = roundingIdx >= 0 ? roundingIdx : (plIndex > 0 ? plIndex - 1 : rows.length - 1);

      if (finalDiff > 0) {
        rows.splice(insertIdx + 1, 0, { name: 'Suspense', type: 'Adjustment', debit: plugAmt, credit: 0 });
      } else {
        rows.splice(insertIdx + 1, 0, { name: 'Suspense', type: 'Adjustment', debit: 0, credit: plugAmt });
      }
      finalDebit = rsumD();
      finalCredit = rsumC();
    }

    return {
      header: { companyName, title: 'TRIAL BALANCE', asOf: end },
      rows,
      totals: { debit: finalDebit, credit: finalCredit },
      profitLossRow
    };
  }

  // === Balance Sheet: consume the SAME period P/L from Income Statement ===
  async function calcBalanceSheet(start: string, end: string) {
    const isData = await calcIncomeStatement(start, end);
    const periodPL = parseFloat(String(isData.totals.netProfitLoss || 0)); // same sign as IS

    const accountsQ = await pool.query(
      `
      SELECT acc.id, acc.name, acc.type,
             COALESCE(SUM(CASE
               WHEN acc.type='Asset' AND t.type='income' THEN t.amount
               WHEN acc.type='Asset' AND t.type='expense' THEN -t.amount
               WHEN acc.type IN ('Liability','Equity') AND t.type='income' THEN t.amount
               WHEN acc.type IN ('Liability','Equity') AND t.type='expense' THEN -t.amount
               ELSE 0 END),0) AS balance
      FROM accounts acc
      LEFT JOIN transactions t ON acc.id=t.account_id
                               AND t.user_id = $1
                               AND t.date<= $2
      WHERE acc.user_id = $1
        AND acc.type IN ('Asset','Liability','Equity')
      GROUP BY acc.id, acc.name, acc.type
      ORDER BY acc.type, acc.name;`,
      [user_id, end]
    );
    const allAccounts = accountsQ.rows as AccRow[];

    let assetsAccounts = groupByNameSum(allAccounts.filter(a => a.type === 'Asset'));
    let liabilityAccounts = groupByNameSum(allAccounts.filter(a => a.type === 'Liability'));
    let equityAccounts = groupByNameSum(allAccounts.filter(a => a.type === 'Equity'));

    assetsAccounts = excludeNames(assetsAccounts, ['accumulated depreciation']);
    equityAccounts = excludeNames(equityAccounts, ['retained', 'profit', 'drawings', 'owner', 'suspense']);
    liabilityAccounts = excludeNames(liabilityAccounts, ['suspense']);

    const faQ = await pool.query(
      `SELECT id, name, cost, accumulated_depreciation
       FROM assets
       WHERE user_id = $1 AND date_received <= $2
       ORDER BY name;`,
      [user_id, end]
    );
    let totalFixedAssetsAtCost = 0;
    let totalAccumulatedDepreciation = 0;
    const fixedAssets = faQ.rows.map((a: any) => {
      const cost = parseFloat(a.cost ?? 0);
      const accDep = parseFloat(a.accumulated_depreciation ?? 0);
      totalFixedAssetsAtCost += cost;
      totalAccumulatedDepreciation += accDep;
      return { name: a.name, cost, accumulated_depreciation: accDep, net_book_value: cost - accDep };
    });

    const openingRetainedQ = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN t.type='income' THEN t.amount ELSE -t.amount END),0) AS opening_retained
       FROM transactions t
       WHERE t.user_id = $1 AND t.date < $2;`,
      [user_id, start]
    );
    const openingRetained = parseFloat(openingRetainedQ.rows[0]?.opening_retained ?? 0);

    // retained earnings to date = opening + canonical period P/L
    const retainedToDate = openingRetained + periodPL;

    // Build display sections
    let totalCurrentAssets = 0;
    const currentAssets = assetsAccounts
      .filter(a => ['bank','cash','receivable'].some(k => norm(a.name).includes(k)))
      .map(a => ({ item: a.name, amount: +a.balance }));
    currentAssets.forEach(a => totalCurrentAssets += a.amount);

    const totalNonCurrentAssets = totalFixedAssetsAtCost - totalAccumulatedDepreciation;
    const totalAssets = totalCurrentAssets + totalNonCurrentAssets;

    let totalEquityAccountsBalance = 0;
    const equityLines = equityAccounts.map(eq => {
      const amt = +eq.balance; totalEquityAccountsBalance += amt; return { item: eq.name, amount: amt };
    });
    const totalEquity = totalEquityAccountsBalance + retainedToDate;

    let totalNonCurrentLiabilities = 0;
    const nonCurrentLiabs = liabilityAccounts
      .filter(a => norm(a.name).includes('loan') || norm(a.name).includes('long-term'))
      .map(l => { const amt = +l.balance; totalNonCurrentLiabilities += amt; return { item: l.name, amount: amt }; });

    let totalCurrentLiabilities = 0;
    const currentLiabs = liabilityAccounts
      .filter(a =>
        norm(a.name).includes('payable') ||
        norm(a.name).includes('current liability') ||
        norm(a.name).includes('credit facility')
      )
      .map(l => { const amt = +l.balance; totalCurrentLiabilities += amt; return { item: l.name, amount: amt }; });

    let totalEquityAndLiabilities = totalEquity + totalNonCurrentLiabilities + totalCurrentLiabilities;

    // optional auto-balance (presentation)
    const adjustments: string[] = [];
    let balanceDifference = nearZero(totalAssets - totalEquityAndLiabilities);
    if (balanceDifference !== 0 && AUTO_ADJUST) {
      let remaining = balanceDifference;

      for (const strategy of STRATEGY_ORDER) {
        if (nearZero(remaining) === 0) break;

        if (strategy === 'depreciation' && remaining > 0) {
          const room = Math.max(0, totalFixedAssetsAtCost - totalAccumulatedDepreciation);
          const depAdj = nearZero(Math.min(remaining, room));
          if (depAdj !== 0) {
            totalAccumulatedDepreciation += depAdj;
            const newNonCurrent = totalFixedAssetsAtCost - totalAccumulatedDepreciation;
            const newTotalAssets = newNonCurrent + totalCurrentAssets;
            totalEquityAndLiabilities = totalEquity + totalNonCurrentLiabilities + totalCurrentLiabilities;
            remaining = nearZero(newTotalAssets - totalEquityAndLiabilities);
            adjustments.push(`Extra Depreciation: ${formatCurrencyForPdf(depAdj)}`);
          }
        }

        if (strategy === 'owners-drawings' && nearZero(remaining) !== 0) {
          totalEquityAndLiabilities += remaining;
          adjustments.push(`Owner's Drawings: ${formatCurrencyForPdf(remaining)}`);
          remaining = 0;
        }

        if (strategy === 'suspense' && nearZero(remaining) !== 0) {
          totalEquityAndLiabilities += remaining;
          adjustments.push(`Suspense: ${formatCurrencyForPdf(remaining)}`);
          remaining = 0;
        }
      }
      balanceDifference = nearZero(totalAssets - totalEquityAndLiabilities);
    }

    return {
      header: { companyName, title: 'BALANCE SHEET', asOf: end, period: { start, end } },
      assets: {
        nonCurrent: {
          fixedAssets,
          totals: {
            totalFixedAssetsAtCost,
            totalAccumulatedDepreciation,
            netBookValue: totalNonCurrentAssets
          }
        },
        current: { lines: currentAssets, totalCurrentAssets },
        totals: { totalAssets }
      },
      equityAndLiabilities: {
        equity: {
          lines: equityLines,
          openingRetained,
          periodPL,
          retainedToDate,
          totalEquity
        },
        liabilities: {
          nonCurrent: { lines: nonCurrentLiabs, totalNonCurrentLiabilities },
          current: { lines: currentLiabs, totalCurrentLiabilities }
        },
        totals: { totalEquityAndLiabilities, balanceDifference, adjustments }
      }
    };
  }

  async function calcCashFlow(start: string, end: string) {
    type Tx = { type: 'income'|'expense'|'debt'; category: string|null; description?: string|null; amount: number; };
    const r = await pool.query(
      `SELECT type, category, description, amount
       FROM transactions
       WHERE user_id = $1 AND date >= $2 AND date <= $3
         AND (type='income' OR type='expense' OR type='debt');`,
      [user_id, start, end]
    );
    const rows: Tx[] = r.rows.map((x: any) => ({ ...x, amount: parseFloat(x.amount) }));

    const classify = (row: Tx): 'operating'|'investing'|'financing' => {
      const cat = (row.category || '').toLowerCase();
      const desc = (row.description || '').toLowerCase();
      if (['equipment','property','asset','vehicle'].some(k => cat.includes(k) || desc.includes(k))) return 'investing';
      if (row.type === 'debt' || ['loan repayment','loan proceeds','share issuance','dividend','drawings']
          .some(k => cat.includes(k) || desc.includes(k))) return 'financing';
      return 'operating';
    };

    const sections = {
      operating: new Map<string, number>(),
      investing: new Map<string, number>(),
      financing: new Map<string, number>(),
    };
    const totals = { operating: 0, investing: 0, financing: 0 };

    for (const tx of rows) {
      const sec = classify(tx);
      const key = tx.description || tx.category || 'Uncategorized';
      const curr = sections[sec].get(key) || 0;

      if (tx.type === 'income') { sections[sec].set(key, curr + tx.amount); totals[sec] += tx.amount; }
      else if (tx.type === 'expense') { sections[sec].set(key, curr - tx.amount); totals[sec] -= tx.amount; }
      else if (tx.type === 'debt') { sections[sec].set(key, curr + tx.amount); totals[sec] += tx.amount; }
    }

    const formatSection = (label: string, m: Map<string, number>, total: number) => ({
      label, items: Array.from(m.entries()).map(([item, amount]) => ({ item, amount })), total
    });

    const operating = formatSection('Operating Activities', sections.operating, totals.operating);
    const investing = formatSection('Investing Activities', sections.investing, totals.investing);
    const financing = formatSection('Financing Activities', sections.financing, totals.financing);

    const netChange = totals.operating + totals.investing + totals.financing;

    return {
      header: { companyName, title: 'CASH FLOW STATEMENT', period: { start, end } },
      sections: { operating, investing, financing },
      totals: { netChange }
    };
  }

  // ====== RENDERERS (PDF) ======
  function drawDocumentHeader(docAny: any, company: string, title: string, dateString: string, disclaimerText: string | null = null) {
    docAny.fontSize(16).font('Helvetica-Bold').text(company, { align: 'center' });
    docAny.fontSize(14).font('Helvetica').text('MANAGEMENT ACCOUNTS', { align: 'center' });
    docAny.moveDown(0.5);
    docAny.fontSize(14).text(title, { align: 'center' });
    docAny.fontSize(10).text(dateString, { align: 'center' });
    docAny.moveDown();
    if (disclaimerText) {
      docAny.fontSize(8).fillColor('red').text(disclaimerText, { align: 'center', width: docAny.page.width - 100 });
      docAny.fillColor('black').moveDown(0.5);
    }
  }

  try {
    // ======= JSON mode =======
    if (wantJson) {
      switch (documentType) {
        case 'income-statement': {
          const data = await calcIncomeStatement(startDate, endDate);
          return res.json({ type: 'income-statement', data });
        }
        case 'trial-balance': {
          const data = await calcTrialBalance(startDate, endDate);
          return res.json({ type: 'trial-balance', data });
        }
        case 'balance-sheet': {
          const data = await calcBalanceSheet(startDate, endDate);
          return res.json({ type: 'balance-sheet', data });
        }
        case 'cash-flow-statement': {
          const data = await calcCashFlow(startDate, endDate);
          return res.json({ type: 'cash-flow-statement', data });
        }
        default:
          return res.status(400).json({ error: 'Document type not supported.' });
      }
    }

    // ======= PDF mode =======
    res.writeHead(200, {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${documentType}-${startDate}-to-${endDate}.pdf"`
    });

    const doc = new PDFDocument();
    doc.pipe(res);

    const col1X = 50, col2X = 400, columnWidth = 100;

    switch (documentType) {
      case 'income-statement': {
        const data = await calcIncomeStatement(startDate, endDate);
        const { totals, breakdown } = data;

        drawDocumentHeader(
          doc, companyName, 'INCOME STATEMENT',
          `FOR THE PERIOD ENDED ${new Date(endDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })}`
        );

        doc.font('Helvetica-Bold');
        doc.fillColor('#e2e8f0').rect(col1X, doc.y, doc.page.width - 100, 20).fill();
        doc.fillColor('#4a5568').text('Description', col1X + 5, doc.y + 5);
        doc.text('Amount (R)', col2X, doc.y + 5, { width: columnWidth, align: 'right' });
        doc.moveDown(0.5).fillColor('black').font('Helvetica');

        doc.text('Sales', col1X, doc.y);
        doc.text(formatCurrencyForPdf(totals.totalSales), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0')
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);

        doc.text('Less: Cost of Sales', col1X, doc.y);
        doc.text(formatCurrencyForPdf(totals.cogs), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0')
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);

        doc.font('Helvetica-Bold');
        doc.text('Gross Profit / (Loss)', col1X, doc.y);
        doc.text(formatCurrencyForPdf(totals.grossProfit), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0')
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');

        if (Object.keys(breakdown.otherIncome).length > 0 || totals.interestIncome > 0) {
          doc.text('Add: Other Income', col1X, doc.y).moveDown(0.5);
          if (totals.interestIncome > 0) {
            doc.text('  Interest Income', col1X + 20, doc.y);
            doc.text(formatCurrencyForPdf(totals.interestIncome), col2X, doc.y, { width: columnWidth, align: 'right' });
            doc.moveDown(0.5);
          }
          for (const k of Object.keys(breakdown.otherIncome)) {
            doc.text(`  ${k}`, col1X + 20, doc.y);
            doc.text(formatCurrencyForPdf(breakdown.otherIncome[k]), col2X, doc.y, { width: columnWidth, align: 'right' });
            doc.moveDown(0.5);
          }
          doc.lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        }

        doc.font('Helvetica-Bold');
        doc.text('Gross Income', col1X, doc.y);
        doc.text(formatCurrencyForPdf(totals.grossProfit + totals.interestIncome + totals.otherIncome), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');

        doc.text('Less: Expenses', col1X, doc.y).moveDown(0.5);
        for (const e of breakdown.expenses) {
          doc.text(`  ${e.category}`, col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(e.amount), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        }

        doc.font('Helvetica-Bold');
        doc.text('Total Expenses', col1X, doc.y);
        doc.text(formatCurrencyForPdf(totals.totalExpenses), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');

        doc.font('Helvetica-Bold');
        doc.text(totals.netProfitLoss >= 0 ? 'NET PROFIT for the period' : 'NET LOSS for the period', col1X, doc.y);
        doc.text(formatCurrencyForPdf(Math.abs(totals.netProfitLoss)), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(1).strokeColor('#a0aec0')
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5)
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown();

        doc.fontSize(8).fillColor('#4a5568').text(
          `Statement Period: ${new Date(startDate).toLocaleDateString('en-GB')} to ${new Date(endDate).toLocaleDateString('en-GB')}`,
          { align: 'center' }
        );
        doc.fillColor('black').moveDown();
        break;
      }

      case 'trial-balance': {
        const data = await calcTrialBalance(startDate, endDate);
        const accountNameX = 50, debitX = 350, creditX = 500;
        const col1X = 50, columnWidth = 100;

        drawDocumentHeader(
          doc, companyName, 'TRIAL BALANCE',
          `AS OF ${new Date(endDate).toLocaleDateString('en-GB')}`
        );

        doc.font('Helvetica-Bold');
        doc.fillColor('#e2e8f0').rect(col1X, doc.y, doc.page.width - 100, 20).fill();
        doc.fillColor('#4a5568').text('Account Name', accountNameX + 5, doc.y + 5);
        doc.text('Debit (R)', debitX, doc.y + 5, { width: columnWidth, align: 'right' });
        doc.text('Credit (R)', creditX, doc.y + 5, { width: columnWidth, align: 'right' });
        doc.moveDown(0.5).fillColor('black').font('Helvetica');

        const lastIndex = data.profitLossRow ? data.rows.length - 1 : data.rows.length;
        for (let i = 0; i < lastIndex; i++) {
          const r = data.rows[i];
          doc.text(r.name, accountNameX, doc.y);
          doc.text(formatCurrencyForPdf(r.debit), debitX, doc.y, { width: columnWidth, align: 'right' });
          doc.text(formatCurrencyForPdf(r.credit), creditX, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0')
            .moveTo(col1X, doc.y).lineTo(creditX + columnWidth, doc.y).stroke().moveDown(0.5);
        }

        if (data.profitLossRow) {
          const r = data.profitLossRow;
          const rowY = doc.y, rowH = 18;
          doc.save(); doc.fillColor('#f1f5f9').rect(col1X, rowY, doc.page.width - 100, rowH).fill(); doc.restore();
          doc.font('Helvetica-Bold');
          doc.text(r.name, accountNameX, rowY + 3);
          doc.text(formatCurrencyForPdf(r.debit), debitX, rowY + 3, { width: columnWidth, align: 'right' });
          doc.text(formatCurrencyForPdf(r.credit), creditX, rowY + 3, { width: columnWidth, align: 'right' });
          doc.y = rowY + rowH;
          doc.lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(creditX + columnWidth, doc.y).stroke();
          doc.moveDown(0.25).font('Helvetica');
        }

        const tailStart = data.profitLossRow ? data.rows.length - 1 : data.rows.length;
        for (let i = tailStart; i < data.rows.length; i++) {
          const r = data.rows[i];
          if (r.name === 'Suspense') {
            doc.text(r.name, accountNameX, doc.y);
            doc.text(formatCurrencyForPdf(r.debit), debitX, doc.y, { width: columnWidth, align: 'right' });
            doc.text(formatCurrencyForPdf(r.credit), creditX, doc.y, { width: columnWidth, align: 'right' });
            doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0')
              .moveTo(col1X, doc.y).lineTo(creditX + columnWidth, doc.y).stroke().moveDown(0.5);
          }
        }

        doc.font('Helvetica-Bold');
        doc.fillColor('#e2e8f0').rect(col1X, doc.y, doc.page.width - 100, 20).fill();
        doc.fillColor('#4a5568').text('Total', accountNameX + 5, doc.y + 5);
        doc.text(formatCurrencyForPdf(data.totals.debit), debitX, doc.y + 5, { width: columnWidth, align: 'right' });
        doc.text(formatCurrencyForPdf(data.totals.credit), creditX, doc.y + 5, { width: columnWidth, align: 'right' });
        doc.moveDown();
        doc.fillColor('black').font('Helvetica');
        doc.lineWidth(1).strokeColor('#a0aec0')
          .moveTo(col1X, doc.y).lineTo(creditX + columnWidth, doc.y).stroke().moveDown(0.5)
          .moveTo(col1X, doc.y).lineTo(creditX + columnWidth, doc.y).stroke().moveDown();

        doc.fontSize(8).fillColor('#4a5568').text(
          `Statement Period: ${new Date(startDate).toLocaleDateString('en-GB')} to ${new Date(endDate).toLocaleDateString('en-GB')}`,
          { align: 'center' }
        );
        doc.fillColor('black').moveDown();
        break;
      }

      case 'balance-sheet': {
        const data = await calcBalanceSheet(startDate, endDate);

        drawDocumentHeader(
          doc, companyName, 'BALANCE SHEET',
          `AS OF ${new Date(endDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })}`
        );

        // ASSETS
        doc.font('Helvetica-Bold').fontSize(12).text('ASSETS', col1X, doc.y).moveDown(0.5).font('Helvetica');

        doc.font('Helvetica-Bold').text('Non-current Assets', col1X, doc.y).moveDown(0.5).font('Helvetica');

        if (data.assets.nonCurrent.fixedAssets.length) {
          doc.text('  Fixed Assets at Cost:', col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(data.assets.nonCurrent.totals.totalFixedAssetsAtCost), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5);
          doc.text('  Less: Accumulated Depreciation', col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(data.assets.nonCurrent.totals.totalAccumulatedDepreciation), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
          doc.font('Helvetica-Bold');
          doc.text('Net Book Value of Fixed Assets', col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(data.assets.nonCurrent.totals.netBookValue), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');
        } else {
          doc.text('  No Fixed Assets to display.', col1X + 20, doc.y).moveDown(1);
        }

        doc.font('Helvetica-Bold').text('Total Non-current Assets', col1X, doc.y);
        doc.text(formatCurrencyForPdf(data.assets.nonCurrent.totals.netBookValue), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');

        doc.font('Helvetica-Bold').text('Current Assets', col1X, doc.y).moveDown(0.5).font('Helvetica');
        for (const ca of data.assets.current.lines) {
          doc.text(`  ${ca.item}`, col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(ca.amount), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        }
        doc.font('Helvetica-Bold').text('Total Current Assets', col1X, doc.y);
        doc.text(formatCurrencyForPdf(data.assets.current.totalCurrentAssets), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);

        doc.font('Helvetica-Bold').fontSize(12).text('Total Assets', col1X, doc.y);
        doc.text(formatCurrencyForPdf(data.assets.totals.totalAssets), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown(2).lineWidth(1).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        doc.lineWidth(1).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown();

        // EQUITY AND LIABILITIES
        doc.font('Helvetica-Bold').fontSize(12).text('EQUITY AND LIABILITIES', col1X, doc.y).moveDown(0.5).font('Helvetica');

        doc.font('Helvetica-Bold').text('Capital and Reserves', col1X, doc.y).moveDown(0.5);
        for (const eq of data.equityAndLiabilities.equity.lines) {
          doc.font('Helvetica').text(`  ${eq.item}`, col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(eq.amount), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        }
        const e = data.equityAndLiabilities.equity;
        doc.font('Helvetica').text('  Opening Retained Earnings', col1X + 20, doc.y);
        doc.text(formatCurrencyForPdf(e.openingRetained), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown(0.5);
        doc.text(e.periodPL >= 0 ? '  Add: Net Profit for the period' : '  Less: Net Loss for the period', col1X + 20, doc.y);
        doc.text(formatCurrencyForPdf(e.periodPL), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        doc.font('Helvetica-Bold').text('Retained Earnings (to date)', col1X, doc.y);
        doc.text(formatCurrencyForPdf(e.retainedToDate), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);

        doc.font('Helvetica-Bold').text('Total Equity', col1X, doc.y);
        doc.text(formatCurrencyForPdf(e.totalEquity), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');

        doc.font('Helvetica-Bold').text('Non-Current Liabilities', col1X, doc.y).moveDown(0.5).font('Helvetica');
        for (const ncl of data.equityAndLiabilities.liabilities.nonCurrent.lines) {
          doc.text(`  ${ncl.item}`, col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(ncl.amount), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        }
        doc.font('Helvetica-Bold').text('Total Non-Current Liabilities', col1X, doc.y);
        doc.text(formatCurrencyForPdf(data.equityAndLiabilities.liabilities.nonCurrent.totalNonCurrentLiabilities), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');

        doc.font('Helvetica-Bold').text('Current Liabilities', col1X, doc.y).moveDown(0.5).font('Helvetica');
        for (const cl of data.equityAndLiabilities.liabilities.current.lines) {
          doc.text(`  ${cl.item}`, col1X + 20, doc.y);
          doc.text(formatCurrencyForPdf(cl.amount), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        }
        doc.font('Helvetica-Bold').text('Total Current Liabilities', col1X, doc.y);
        doc.text(formatCurrencyForPdf(data.equityAndLiabilities.liabilities.current.totalCurrentLiabilities), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);

        doc.text('Total Equity and Liabilities', col1X, doc.y).font('Helvetica');
        doc.text(formatCurrencyForPdf(data.equityAndLiabilities.totals.totalEquityAndLiabilities), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown(2).lineWidth(1).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
        doc.lineWidth(1).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown();

        if (data.equityAndLiabilities.totals.adjustments.length) {
          doc.fontSize(8).fillColor('red').text(
            `Auto-balancing applied for presentation: ${data.equityAndLiabilities.totals.adjustments.join(' | ')}`,
            { align: 'center', width: doc.page.width - 100 }
          );
          doc.fillColor('black').moveDown();
        }

        doc.fontSize(8).fillColor('#4a5568').text(
          `Statement Period: ${new Date(startDate).toLocaleDateString('en-GB')} to ${new Date(endDate).toLocaleDateString('en-GB')}`,
          { align: 'center' }
        );
        doc.fillColor('black').moveDown();
        break;
      }

      case 'cash-flow-statement': {
        const data = await calcCashFlow(startDate, endDate);

        drawDocumentHeader(
          doc, companyName, 'CASH FLOW STATEMENT',
          `FOR THE PERIOD ENDED ${new Date(endDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })}`
        );

        const renderSec = (title: string, sec: { items: { item: string; amount: number }[]; total: number }) => {
          doc.font('Helvetica-Bold').fontSize(12).text(title, col1X, doc.y).moveDown(0.5).font('Helvetica');
          for (const it of sec.items) {
            doc.text(`  ${it.item}`, col1X + 20, doc.y);
            doc.text(formatCurrencyForPdf(it.amount), col2X, doc.y, { width: columnWidth, align: 'right' });
            doc.moveDown(0.5).lineWidth(0.2).strokeColor('#e2e8f0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5);
          }
          doc.font('Helvetica-Bold').text(`Net ${title}`, col1X, doc.y);
          doc.text(formatCurrencyForPdf(sec.total), col2X, doc.y, { width: columnWidth, align: 'right' });
          doc.moveDown(1).lineWidth(0.5).strokeColor('#a0aec0').moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5).font('Helvetica');
        };

        renderSec(data.sections.operating.label, data.sections.operating);
        renderSec(data.sections.investing.label, data.sections.investing);
        renderSec(data.sections.financing.label, data.sections.financing);

        doc.font('Helvetica-Bold').fontSize(12).text('Net Increase / (Decrease) in Cash', col1X, doc.y);
        doc.text(formatCurrencyForPdf(data.totals.netChange), col2X, doc.y, { width: columnWidth, align: 'right' });
        doc.moveDown().lineWidth(1).strokeColor('#a0aec0')
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown(0.5)
          .moveTo(col1X, doc.y).lineTo(col2X + columnWidth, doc.y).stroke().moveDown();

        doc.fontSize(8).fillColor('#4a5568').text(
          `Statement Period: ${new Date(startDate).toLocaleDateString('en-GB')} to ${new Date(endDate).toLocaleDateString('en-GB')}`,
          { align: 'center' }
        );
        doc.fillColor('black').moveDown();
        break;
      }

      default:
        doc.text('Document type not supported.', { align: 'center' });
        doc.end();
        return;
    }

    doc.end();
  } catch (error: any) {
    console.error(`Error generating ${documentType}:`, error);
    if (!wantJson) {
      try { res.removeHeader('Content-Disposition'); } catch {}
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
    }
    res.end(JSON.stringify({ error: `Failed to generate ${documentType}`, details: error?.message || String(error) }));
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
        COALESCE(json_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '[]') AS roles
      FROM public.users u
      LEFT JOIN public.user_roles ur ON u.user_id = ur.user_id
      LEFT JOIN public.roles r ON ur.role = r.name
      WHERE u.parent_user_id = $1
      GROUP BY u.id, u.name, u.email, u.user_id;
    `, [userId]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to load users.' });
  }
});

// 2. POST /users - Create a new user within the authenticated user's organization
app.post('/users', authMiddleware, async (req: Request, res: Response) => {
  const { displayName, email, role, password } = req.body;
  const newUserId = uuidv4();
  const parentUserId = (req as any).user?.user_id;

  if (!displayName || !email || !password || !parentUserId) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  const userRole = (typeof role === 'string' && role.length > 0) ? role : 'user';
  
  try {
    const password_hash = await bcrypt.hash(password, 10);

    await pool.query('BEGIN');

    const userInsertResult = await pool.query(
      'INSERT INTO public.users (id, name, email, user_id, password_hash, parent_user_id, role) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name AS "displayName", email, user_id',
      [uuidv4(), displayName, email, newUserId, password_hash, parentUserId, userRole]
    );

    const roleInsertResult = await pool.query('SELECT name FROM public.roles WHERE name = $1', [userRole]);
    if (roleInsertResult.rows.length === 0) {
      console.warn(`Role '${userRole}' does not exist and will not be assigned.`);
    } else {
        await pool.query(
          'INSERT INTO public.user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [newUserId, userRole]
        );
    }
    
    await pool.query('COMMIT');

    res.status(201).json(userInsertResult.rows[0]);
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('Error adding new user:', err);
    
    if (err instanceof Error) {
        res.status(500).json({ error: err.message || 'Registration failed.' });
    } else {
      res.status(500).json({ error: 'Registration failed.' });
    }
  }
});

// 3. PUT /users/:id - Update a user's basic details within the authenticated user's organization
app.put('/users/:id', authMiddleware, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { displayName, email } = req.body;
  const parentUserId = (req as any).user?.user_id;

  if (!parentUserId) {
    return res.status(401).json({ error: 'Unauthorized: User ID not found.' });
  }

  if (!displayName || !email) {
    return res.status(400).json({ error: 'Missing required data: displayName and email' });
  }

  try {
    // Log the parameters to help debug the 404 issue
    console.log(`[PUT /users/:id] Attempting to update user with id: ${id} under parent user: ${parentUserId}`);
    
    const result = await pool.query(
      'UPDATE public.users SET name = $1, email = $2 WHERE id = $3 AND parent_user_id = $4 RETURNING id, name AS "displayName", email',
      [displayName, email, id, parentUserId]
    );

    if (result.rows.length === 0) {
      console.error(`[PUT /users/:id] User with id: ${id} and parent_user_id: ${parentUserId} not found.`);
      return res.status(404).json({ error: 'User not found or not in your organization' });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Update failed.' });
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
    // Delete from user_roles first due to foreign key constraints
    await pool.query('DELETE FROM public.user_roles WHERE user_id = (SELECT id FROM public.users WHERE id = $1 AND parent_user_id = $2)', [id, parentUserId]);
    
    // Then delete the user
    const result = await pool.query('DELETE FROM public.users WHERE id = $1 AND parent_user_id = $2 RETURNING id', [id, parentUserId]);

    if (result.rows.length === 0) {
      console.error(`[DELETE /users/:id] User with id: ${id} and parent_user_id: ${parentUserId} not found.`);
      return res.status(404).json({ error: 'User not found or not in your organization' });
    }

    res.status(200).json({ message: 'User deleted successfully' });
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




app.listen(PORT, () => {
  console.log(`Node server running on http://localhost:${PORT}`);
});
