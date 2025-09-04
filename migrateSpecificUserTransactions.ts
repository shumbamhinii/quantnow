// migrateSpecificUserTransactions.ts
import { Pool } from 'pg';

// --- DIRECT DATABASE CONNECTION ---
const pool = new Pool({
  connectionString:
    "postgresql://qbeta_db:E5sNOxattCokbXt7aWqDSIFi2YHznCYl@dpg-d2ndml75r7bs73fes2d0-a.oregon-postgres.render.com/qbeta_db_jg0t",
  max: 5,
  idleTimeoutMillis: 30000,
  ssl: { rejectUnauthorized: false },
});
// --- END DIRECT DATABASE CONNECTION ---

// --- Target User ID ---
const TARGET_USER_ID = 'ee9af963-30ca-44d8-9536-83ddf87e7be3';
// --- END Target User ID ---

async function migrateUserTransactions() {
  console.log(`[MIGRATION SCRIPT] Starting migration for user ${TARGET_USER_ID}...`);
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Fetch unmigrated transactions for the TARGET user
    console.log(`[MIGRATION SCRIPT] Fetching unmigrated transactions for user ${TARGET_USER_ID}...`);
    const transactionsRes = await client.query(
      `SELECT id, "type", amount, description, "date", category, account_id, original_text, "source", confirmed, user_id, migrated_to_journal
       FROM public.transactions
       WHERE user_id = $1 AND (migrated_to_journal IS NULL OR migrated_to_journal = FALSE)
       ORDER BY "date", id`,
      [TARGET_USER_ID]
    );
    const transactions = transactionsRes.rows;
    console.log(`[MIGRATION SCRIPT] Found ${transactions.length} transactions to migrate for user ${TARGET_USER_ID}.`);

    if (transactions.length === 0) {
      await client.query('COMMIT');
      console.log(`[MIGRATION SCRIPT] No transactions to migrate for user ${TARGET_USER_ID}.`);
      console.log(JSON.stringify({ message: `No transactions to migrate for user ${TARGET_USER_ID}.`, migrated: 0 }, null, 2));
      return;
    }

    // 2. Find the default Cash/Bank account for the TARGET user
    console.log(`[MIGRATION SCRIPT] Finding default Cash/Bank account for user ${TARGET_USER_ID}...`);
    const cashAccountRes = await client.query(
      `SELECT id FROM public.accounts 
       WHERE user_id = $1 AND (name ILIKE '%cash%' OR name ILIKE '%bank%') AND is_active = TRUE AND is_postable = TRUE
       ORDER BY id LIMIT 1`,
      [TARGET_USER_ID]
    );
    const cashAccountId = cashAccountRes.rows[0]?.id;
    if (!cashAccountId) {
      await client.query('ROLLBACK');
      const errorMsg = `[MIGRATION SCRIPT ERROR] No default Cash/Bank account found for user ${TARGET_USER_ID}.`;
      console.error(errorMsg);
      console.log(JSON.stringify({ error: errorMsg }, null, 2));
      return;
    }
    console.log(`[MIGRATION SCRIPT] Using Cash/Bank account ID: ${cashAccountId} for user ${TARGET_USER_ID}`);

    let migratedCount = 0;
    const errors: string[] = [];

    // 3. Process each transaction with individual error handling
    console.log(`[MIGRATION SCRIPT] Starting to process ${transactions.length} transactions for user ${TARGET_USER_ID}...`);
    for (const tx of transactions) {
      try { // --- WRAP EACH TRANSACTION IN ITS OWN TRY/CATCH ---
        const txId = tx.id;
        const txType = tx.type; // 'income', 'expense', 'transfer', 'adjustment'
        const txAmount = parseFloat(tx.amount) || 0;
        const txDescription = tx.description || tx.original_text || 'Migrated Transaction';
        const txDate = tx.date; // 'YYYY-MM-DD'
        const txAccountId = tx.account_id; // Primary account
        
        console.log(`[MIGRATION SCRIPT] Processing transaction ID ${txId} (${txType}, R${txAmount}) for user ${TARGET_USER_ID}...`);

        // Skip if amount is zero or no primary account
        if (txAmount === 0) {
          const warnMsg = `[MIGRATION SCRIPT WARN] Skipping transaction ID ${txId} for user ${TARGET_USER_ID}: Amount is zero.`;
          console.warn(warnMsg);
          errors.push(`Transaction ID ${txId}: Skipped (Amount is zero)`);
          continue;
        }
        if (!txAccountId) {
          const warnMsg = `[MIGRATION SCRIPT WARN] Skipping transaction ID ${txId} for user ${TARGET_USER_ID}: No primary account_id.`;
          console.warn(warnMsg);
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
          const warnMsg = `[MIGRATION SCRIPT WARN] Skipping transaction ID ${txId} for user ${TARGET_USER_ID}: Type '${txType}' not supported for automatic migration.`;
          console.warn(warnMsg);
          errors.push(`Transaction ID ${txId}: Skipped (Type '${txType}' not supported)`);
          continue;
        }

        // 5. Create Journal Entry (WITHOUT the 'source' column for now)
        // --- REMOVE 'source' from INSERT and VALUES ---
        const jeRes = await client.query(
          `INSERT INTO public.journal_entries (entry_date, memo, user_id)
           VALUES ($1, $2, $3)
           RETURNING id`,
          [txDate, txDescription, TARGET_USER_ID] // <-- Removed source parameter
        );
        // --- END REMOVE ---
        const journalEntryId = jeRes.rows[0].id;
        console.log(`[MIGRATION SCRIPT] Created Journal Entry ID ${journalEntryId} for transaction ${txId} (user ${TARGET_USER_ID}).`);

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
          lineParams.push(l.entryId, l.accountId, TARGET_USER_ID, l.debit, l.credit); // <-- Use target user ID
        }
        await client.query(
          `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
           VALUES ${lineValues.join(", ")}`,
          lineParams
        );
        console.log(`[MIGRATION SCRIPT] Created ${lines.length} Journal Lines for entry ${journalEntryId} (user ${TARGET_USER_ID}).`);

        // --- NEW: Also insert into public.transactions table ---
        // Prepare data for the transactions table insert
        // Determine transaction type for the transactions table based on journal entry logic
        const transactionTableType: 'income' | 'expense' = txType === 'income' ? 'income' : 'expense'; // Simplified mapping
        // Determine category for transactions table (could be improved)
        let transactionCategory = tx.category || 'Imported';
        if (transactionTableType === 'income' && !tx.category) {
            transactionCategory = 'Sales Revenue'; // Default income category
        } else if (transactionTableType === 'expense' && !tx.category) {
            transactionCategory = 'Other expenses'; // Default expense category
        }
        
        // Insert into public.transactions
        await client.query(
          `INSERT INTO public.transactions (user_id, type, amount, description, date, category, account_id, original_text, source, confirmed)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            TARGET_USER_ID,              // user_id
            transactionTableType,       // type (income/expense)
            Math.abs(txAmount),         // amount (always positive in transactions table?)
            txDescription,              // description
            txDate,                     // date
            transactionCategory,        // category
            txAccountId,                // account_id (primary account from original transaction)
            tx.original_text || txDescription, // original_text
            `migration-script-${tx.source || 'manual'}`, // source
            true                        // confirmed
          ]
        );
        console.log(`[MIGRATION SCRIPT] Also inserted record into public.transactions for transaction ${txId} (user ${TARGET_USER_ID}).`);
        // --- END NEW ---

        // 7. Mark original transaction as migrated
        await client.query(
          `UPDATE public.transactions SET migrated_to_journal = TRUE WHERE id = $1 AND user_id = $2`, // <-- Ensure user_id match
          [txId, TARGET_USER_ID] // <-- Use target user ID
        );
        console.log(`[MIGRATION SCRIPT] Marked transaction ID ${txId} as migrated for user ${TARGET_USER_ID}.`);

        migratedCount++;

      } catch (txError: any) { // --- CATCH INDIVIDUAL TRANSACTION ERRORS ---
        const errorMsg = `[MIGRATION SCRIPT ERROR] Failed to migrate transaction ID ${tx.id} for user ${TARGET_USER_ID}: ${txError.message}`;
        console.error(errorMsg);
        errors.push(`Transaction ID ${tx.id}: Failed (${txError.message})`);
        // Continue processing other transactions instead of aborting the whole batch
        // The outer transaction (BEGIN/COMMIT) will still commit successfully migrated ones
      }
    }

    await client.query('COMMIT');
    const successMsg = `[MIGRATION SCRIPT] Migration completed for user ${TARGET_USER_ID}. Migrated ${migratedCount} transactions.`;
    console.log(successMsg);
    console.log(JSON.stringify({ 
      message: successMsg, 
      migrated: migratedCount,
      errors: errors.length > 0 ? errors : undefined
    }, null, 2));

  } catch (error: any) {
    await client.query('ROLLBACK');
    const errorMsg = `[MIGRATION SCRIPT ERROR] Migration failed for user ${TARGET_USER_ID}: ${error.message}`;
    console.error(errorMsg);
    console.log(JSON.stringify({ error: errorMsg, detail: error.message }, null, 2));
  } finally {
    client.release();
    await pool.end(); // Close the pool connection when done
    console.log(`[MIGRATION SCRIPT] Database connection pool closed.`);
  }
}

// --- Run the script ---
if (require.main === module) {
    migrateUserTransactions().then(() => {
        console.log("[MIGRATION SCRIPT] Script finished execution.");
        process.exit(0);
    }).catch(err => {
        console.error("[MIGRATION SCRIPT] Unhandled error in script:", err);
        process.exit(1);
    });
}
// --- End Run the script ---