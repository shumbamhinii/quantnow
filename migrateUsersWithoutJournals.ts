import { Pool } from 'pg';

/**
 * CONFIG: use env var in production
 *   PG_CONNECTION_STRING=postgresql://user:pass@host:port/dbname
 */
const pool = new Pool({
  connectionString:
    process.env.PG_CONNECTION_STRING ??
    "postgresql://qbeta_db:E5sNOxattCokbXt7aWqDSIFi2YHznCYl@dpg-d2ndml75r7bs73fes2d0-a.oregon-postgres.render.com/qbeta_db_jg0t",
  max: 5,
  idleTimeoutMillis: 30_000,
  ssl: { rejectUnauthorized: false },
});

/**
 * Pick a default Cash/Bank account for a user:
 * first active, postable account with name like %cash% or %bank%.
 */
async function pickCashOrBankAccountId(client: any, userId: string): Promise<number | null> {
  const { rows } = await client.query(
    `SELECT id
       FROM public.accounts
      WHERE user_id = $1
        AND is_active = TRUE
        AND is_postable = TRUE
        AND (name ILIKE '%cash%' OR name ILIKE '%bank%')
      ORDER BY id
      LIMIT 1`,
    [userId]
  );
  return rows[0]?.id ?? null;
}

/**
 * Core migration for a single user (no touch to transactions table).
 * Only migrates 'income' and 'expense'.
 */
async function migrateUser(client: any, userId: string) {
  console.log(`\n[USER ${userId}] Starting migration…`);

  // Double check idempotence: if any journals exist, skip user.
  const { rows: checkRows } = await client.query(
    `SELECT EXISTS (SELECT 1 FROM public.journal_entries WHERE user_id = $1 LIMIT 1) AS has_entries`,
    [userId]
  );
  if (checkRows[0]?.has_entries) {
    console.log(`[USER ${userId}] Already has journal entries → skipping.`);
    return { migrated: 0, skipped: 0, errors: [] as string[] };
  }

  // Load all transactions for user (keep table intact — no updates)
  const { rows: txRows } = await client.query(
    `SELECT id, "type", amount, description, "date", account_id, original_text
       FROM public.transactions
      WHERE user_id = $1
      ORDER BY "date", id`,
    [userId]
  );
  console.log(`[USER ${userId}] Found ${txRows.length} transactions to inspect.`);

  if (txRows.length === 0) return { migrated: 0, skipped: 0, errors: [] as string[] };

  const cashAccountId = await pickCashOrBankAccountId(client, userId);
  if (!cashAccountId) {
    console.warn(`[USER ${userId}] No Cash/Bank account found → skipping user.`);
    return { migrated: 0, skipped: txRows.length, errors: [`No cash/bank account for user ${userId}`] };
  }

  let migrated = 0;
  let skipped = 0;
  const errors: string[] = [];

  // Wrap the whole user in a transaction but tolerate per-row errors
  await client.query('BEGIN');

  for (const tx of txRows) {
    try {
      const txId = tx.id;
      const ttype = String(tx.type || '').toLowerCase(); // income | expense | (others skipped)
      const amount = Math.abs(parseFloat(tx.amount));     // NUMERIC comes back as string
      const primaryAccountId = tx.account_id ? Number(tx.account_id) : null;
      const memo = tx.description || tx.original_text || 'Migrated Transaction';
      const entryDate = tx.date; // 'YYYY-MM-DD'

      if (!amount || isNaN(amount)) {
        skipped++;
        continue; // zero/invalid amount
      }
      if (!primaryAccountId) {
        skipped++;
        continue; // no target account
      }
      if (ttype !== 'income' && ttype !== 'expense') {
        skipped++;
        continue; // only these two are auto-migrated
      }

      // Map debit/credit:
      // income  → Dr Cash/Bank, Cr Revenue(primary)
      // expense → Dr Expense(primary), Cr Cash/Bank
      let debitAccountId: number;
      let creditAccountId: number;

      if (ttype === 'income') {
        debitAccountId = cashAccountId;
        creditAccountId = primaryAccountId;
      } else {
        debitAccountId = primaryAccountId;
        creditAccountId = cashAccountId;
      }

      // Insert journal entry
      const jeRes = await client.query(
        `INSERT INTO public.journal_entries (entry_date, memo, user_id)
         VALUES ($1, $2, $3)
         RETURNING id`,
        [entryDate, memo, userId]
      );
      const journalEntryId = jeRes.rows[0].id;

      // Insert the two lines
      await client.query(
        `INSERT INTO public.journal_lines (entry_id, account_id, user_id, debit, credit)
         VALUES
           ($1, $2, $3, $4, 0),
           ($1, $5, $3, 0, $4)`,
        [journalEntryId, debitAccountId, userId, amount, creditAccountId]
      );

      migrated++;
    } catch (err: any) {
      errors.push(String(err?.message || err));
      // keep going with the next transaction
    }
  }

  await client.query('COMMIT');

  console.log(`[USER ${userId}] Done. Migrated=${migrated}, Skipped=${skipped}, Errors=${errors.length}`);
  return { migrated, skipped, errors };
}

/**
 * Entry point:
 * 1) Find all users who have transactions but no journal entries.
 * 2) Migrate each user as above (transactions table remains unchanged).
 */
async function main() {
  const client = await pool.connect();
  try {
    // Find candidate users
    const { rows: userRows } = await client.query(
      `SELECT t.user_id
         FROM public.transactions t
    LEFT JOIN public.journal_entries je
           ON je.user_id = t.user_id
     GROUP BY t.user_id
       HAVING COUNT(je.id) = 0`
    );

    if (!userRows.length) {
      console.log('No users require migration (everyone already has journal entries).');
      return;
    }

    console.log(`Users to migrate: ${userRows.length}`);
    const results: Array<{ user: string; migrated: number; skipped: number; errors: string[] }> = [];

    for (const r of userRows) {
      const userId = r.user_id as string;
      const res = await migrateUser(client, userId);
      results.push({ user: userId, ...res });
    }

    // Summary
    const summary = {
      migrated_users: results.length,
      totals: {
        migrated: results.reduce((s, r) => s + r.migrated, 0),
        skipped: results.reduce((s, r) => s + r.skipped, 0),
        users_with_errors: results.filter(r => r.errors.length).length,
      },
      details: results,
    };
    console.log('\n=== MIGRATION SUMMARY ===');
    console.log(JSON.stringify(summary, null, 2));
  } finally {
    client.release();
    await pool.end();
  }
}

// run
if (require.main === module) {
  main()
    .then(() => {
      console.log('Migration script finished.');
      process.exit(0);
    })
    .catch(err => {
      console.error('Migration script failed:', err);
      process.exit(1);
    });
}
