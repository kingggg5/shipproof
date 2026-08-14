export async function findUser(database, email) {
  const query = "SELECT id, email FROM users WHERE email = $1";
  return database.query(query, [email]);
}

export const tlsPolicy = { rejectUnauthorized: true };
