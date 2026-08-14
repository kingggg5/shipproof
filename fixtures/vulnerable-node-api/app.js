// Intentionally vulnerable scanner fixture. Never use in an application.
export async function findUser(database, email) {
  return database.query(`SELECT id, email FROM users WHERE email = '${email}'`);
}

export const unsafeTls = { rejectUnauthorized: false };
