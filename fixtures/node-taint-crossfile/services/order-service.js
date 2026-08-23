// Intentionally vulnerable head-to-head corpus. Never use in an application.
//
// The tainted parameter reaches a concatenated query sink inside this helper.
async function createOrder(productName, quantity) {
  const rows = await db.query(
    "INSERT INTO orders (product, qty) VALUES ('" + productName + "', " + quantity + ")"
  );
  return rows[0];
}

module.exports = { createOrder };
