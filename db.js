const { Pool } = require('pg');

// Here we create a pool of clients
// The pool is handled by the pg code itself.
// So, unless we use transactions, we need not
// worry about creating and destroying clients.
const pool = new Pool({
    connectionString: process.env.DATABASE_CRUD,
    ssl: {
        rejectUnauthorized: false, // Useful for testing purposes
    }
});

module.exports = {
    // The pg code takes the respnsibility of creating and destroying
    // a client for these simple atomic queries,
    async query(t, p){ return await pool.query(t, p); } 
    // We might as well create a function to wrap code to simplify
    // transactions, but we won't need it.
};

