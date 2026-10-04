// Recreates the disposable e2e database before the playground server starts.
import pg from 'pg'

const admin = new pg.Client({ connectionString: process.env.AUTHENTICATION_TEST_DATABASE_URL })
const name = new URL(process.env.AUTHENTICATION_DATABASE_URL).pathname.slice(1)
if (!/^[a-z0-9_]+$/.test(name)) throw new Error(`Unsafe database name ${name}`)
await admin.connect()
await admin.query(`drop database if exists "${name}" with (force)`)
await admin.query(`create database "${name}"`)
await admin.end()
