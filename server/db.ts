import { drizzle } from 'drizzle-orm/neon-http';
import { neon } from '@neondatabase/serverless';
import * as schema from '../shared/schema';

// Validate DATABASE_URL is present
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set!');
  console.error('Please create a .env file with DATABASE_URL=postgresql://user:pass@host:port/dbname');
  console.error('Example: DATABASE_URL=postgresql://cveuser:cvepass@localhost:5432/cve_lab_db');
  process.exit(1);
}

// Create database connection
const sql = neon(process.env.DATABASE_URL);

// Initialize Drizzle ORM with schema
export const db = drizzle(sql, { schema });

// Export schema for convenience
export * from '../shared/schema';

// Helper function to test database connection
export async function testDatabaseConnection(): Promise<boolean> {
  try {
    // Try a simple query
    await sql`SELECT 1 as test`;
    console.log('✅ Database connection successful!');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    console.error('Please ensure:');
    console.error('1. PostgreSQL is running (docker-compose up -d)');
    console.error('2. DATABASE_URL is correct in .env file');
    console.error('3. Database schema is deployed (npm run db:push)');
    return false;
  }
}

// Log connection info on import (but hide sensitive parts)
const dbUrl = process.env.DATABASE_URL;
const sanitizedUrl = dbUrl.replace(/:[^:@]+@/, ':****@'); // Hide password
console.log(`📊 Database configured: ${sanitizedUrl}`);
