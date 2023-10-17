/**
 * <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", padding: 16}}>
 *  <p style={{fontWeight: "normal"}}>An official <a href="https://www.postgresql.org/">PostgreSQL</a> adapter for Auth.js / NextAuth.js.</p>
 *  <a href="https://www.postgresql.org/">
 *   <img style={{display: "block"}} src="/img/adapters/pg.png" width="48" />
 *  </a>
 * </div>
 *
 * ## Installation
 *
 * ```bash npm2yarn2pnpm
 * npm install next-auth @auth/pg-adapter pg
 * ```
 *
 * @module @auth/pg-adapter
 */

import type {
  Adapter,
  AdapterUser,
  VerificationToken,
  AdapterSession,
} from "@auth/core/src/adapters"
import { neon } from "@neondatabase/serverless"

export function mapExpiresAt(account: any): any {
  const expires_at: number = parseInt(account.expires_at)
  return {
    ...account,
    expires_at,
  }
}

function isDate(date: any) {
  return (
    new Date(date).toString() !== "Invalid Date" && !isNaN(Date.parse(date))
  )
}

export function format<T>(obj: Record<string, any>): T {
  for (const [key, value] of Object.entries(obj)) {
    if (value === null) {
      delete obj[key]
    }

    if (isDate(value)) {
      obj[key] = new Date(value)
    }
  }

  return obj as T
}

/**
 * ## Setup
 *
 * The SQL schema for the tables used by this adapter is as follows. Learn more about the models at our doc page on [Database Models](http://localhost:3000/reference/adapters#models).
 * ```sql
 * CREATE TABLE verification_token
 * (
 *   identifier TEXT NOT NULL,
 *   expires TIMESTAMPTZ NOT NULL,
 *   token TEXT NOT NULL,
 *
 *   PRIMARY KEY (identifier, token)
 * );
 *
 * CREATE TABLE accounts
 * (
 *   id SERIAL,
 *   "userId" INTEGER NOT NULL,
 *   type VARCHAR(255) NOT NULL,
 *   provider VARCHAR(255) NOT NULL,
 *   "providerAccountId" VARCHAR(255) NOT NULL,
 *   refresh_token TEXT,
 *   access_token TEXT,
 *   expires_at BIGINT,
 *   id_token TEXT,
 *   scope TEXT,
 *   session_state TEXT,
 *   token_type TEXT,
 *
 *   PRIMARY KEY (id)
 * );
 *
 * CREATE TABLE sessions
 * (
 *   id SERIAL,
 *   "userId" INTEGER NOT NULL,
 *   expires TIMESTAMPTZ NOT NULL,
 *   "sessionToken" VARCHAR(255) NOT NULL,
 *
 *   PRIMARY KEY (id)
 * );
 *
 * CREATE TABLE users
 * (
 *   id SERIAL,
 *   name VARCHAR(255),
 *   email VARCHAR(255),
 *   "emailVerified" TIMESTAMPTZ,
 *   image TEXT,
 *
 *   PRIMARY KEY (id)
 * );
 *
 * ```
 *
 *  ```bash npm2yarn2pnpm
 * npm install pg @auth/pg-adapter next-auth
 * ```
 *
 * ```typescript title="auth.ts"
 * import NextAuth from "next-auth"
 * import GoogleProvider from "next-auth/providers/google"
 * import { PostgresAdapter } from "@auth/pg-adapter"
 * import { Pool } from 'pg'
 *
 * const pool = new Pool({
 *   host: 'localhost',
 *   user: 'database-user',
 *   max: 20,
 *   idleTimeoutMillis: 30000,
 *   connectionTimeoutMillis: 2000,
 * })
 *
 * export default NextAuth({
 *   adapter: PostgresAdapter(pool),
 *   providers: [
 *     GoogleProvider({
 *       clientId: process.env.GOOGLE_CLIENT_ID,
 *       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 *     }),
 *   ],
 * })
 * ```
 *
 */
export default function PostgresAdapter({
  connectionUrl,
}: {
  connectionUrl: string
}): Adapter {
  const sql = neon(connectionUrl)

  return {
    async createVerificationToken(verificationToken) {
      const { identifier, expires, token } = verificationToken
      const [result] = await sql`
        INSERT INTO verification_token ( identifier, expires, token ) 
        VALUES (${identifier}, ${expires}, ${token})
        returning identifier, expires, token
        `
      if (!result) return null

      return format<VerificationToken>(result)
    },
    async useVerificationToken({ identifier, token }) {
      const result = await sql`delete from verification_token
      where identifier = ${identifier} and token = ${token}
      RETURNING identifier, expires, token`

      return result.length !== 0 ? format<VerificationToken>(result[0]) : null
    },

    async createUser(user) {
      const { name, email, emailVerified, image } = user
      const [result] = await sql`
        INSERT INTO users (name, email, "emailVerified", image)
        VALUES (${name}, ${email}, ${emailVerified}, ${image})
        RETURNING id, name, email, "emailVerified", image
      `
      return format<AdapterUser>(result)
    },
    async getUser(id) {
      try {
        const result = await sql`select * from users where id = ${id}`
        return result.length === 0 ? null : format<AdapterUser>(result[0])
      } catch (e) {
        return null
      }
    },
    async getUserByEmail(email) {
      const result = await sql`select * from users where email = ${email}`
      return result.length !== 0 ? format<AdapterUser>(result[0]) : null
    },
    async getUserByAccount({ providerAccountId, provider }) {
      const result = await sql`
          select u.* from users u join accounts a on u.id = a."userId"
          where 
          a.provider = ${provider} 
          and 
          a."providerAccountId" = ${providerAccountId}`

      return result.length !== 0 ? format<AdapterUser>(result[0]) : null
    },
    async updateUser(user) {
      const [oldUser] = await sql`select * from users where id = ${user.id}`

      const newUser = {
        ...oldUser,
        ...user,
      }

      const { id, name, email, emailVerified, image } = newUser
      const [query2] = await sql`
        UPDATE users set
        name = ${name}, email = ${email}, "emailVerified" = ${emailVerified}, image = ${image}
        where id = ${id}
        RETURNING name, id, email, "emailVerified", image
      `
      return format<AdapterUser>(query2)
    },
    async linkAccount(account) {
      const [result] = await sql`
      insert into accounts 
      (
        "userId", 
        provider, 
        type, 
        "providerAccountId", 
        access_token,
        expires_at,
        refresh_token,
        id_token,
        scope,
        session_state,
        token_type
      )
      values (
        ${account.userId}, 
        ${account.provider}, 
        ${account.type}, 
        ${account.providerAccountId}, 
        ${account.access_token}, 
        ${account.expires_at}, 
        ${account.refresh_token}, 
        ${account.id_token}, 
        ${account.scope}, 
        ${account.session_state}, 
        ${account.token_type})
      returning
        id,
        "userId", 
        provider, 
        type, 
        "providerAccountId", 
        access_token,
        expires_at,
        refresh_token,
        id_token,
        scope,
        session_state,
        token_type`

      return mapExpiresAt(result)
    },
    async createSession({ sessionToken, userId, expires }) {
      if (userId === undefined) {
        throw Error(`userId is undef in createSession`)
      }
      const [result] =
        await sql`insert into sessions ("userId", expires, "sessionToken")
                  values (${userId}, ${expires}, ${sessionToken})
                  RETURNING id, "sessionToken", "userId", expires`

      return format<AdapterSession>(result)
    },

    async getSessionAndUser(sessionToken) {
      if (sessionToken === undefined) {
        return null
      }
      const result1 =
        await sql`select * from sessions where "sessionToken" = ${sessionToken}`

      if (result1.length === 0) {
        return null
      }

      let session = format<AdapterSession>(result1[0])

      const result2 =
        await sql`select * from users where id = ${session.userId}`

      if (result2.length === 0) {
        return null
      }
      const user = format<AdapterUser>(result2[0])

      return {
        session,
        user,
      }
    },

    async updateSession(session) {
      const { sessionToken } = session
      const result1 =
        await sql`select * from sessions where "sessionToken" = ${sessionToken}`

      if (result1.length === 0) {
        return null
      }
      const originalSession = format<AdapterSession>(result1[0])

      const newSession: AdapterSession = {
        ...originalSession,
        ...session,
      }

      const [result] = await sql`
        update sessions set
        expires = ${newSession.expires}
        where "sessionToken" = ${newSession.sessionToken}
        returning id, "sessionToken", "userId", expires
      `

      return format<AdapterSession>(result)
    },
    async deleteSession(sessionToken) {
      await sql`delete from sessions where "sessionToken" = ${sessionToken}`
    },
    async unlinkAccount(partialAccount) {
      const { provider, providerAccountId } = partialAccount
      await sql`delete from accounts where "providerAccountId" = ${providerAccountId} and provider = ${provider}`
    },
    async deleteUser(userId: string) {
      await sql.transaction([
        sql`delete from users where id = ${userId}`,
        sql`delete from sessions where "userId" = ${userId}`,
        sql`delete from accounts where "userId" = ${userId}`,
      ])
    },
  }
}
