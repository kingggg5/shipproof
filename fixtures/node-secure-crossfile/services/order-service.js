// Secure counterpart of the vulnerable corpus. Parameterized query sink.
async function createOrder(productName, quantity) {
  const rows = await db.query("INSERT INTO orders (product, qty) VALUES (?, ?)", [
    productName,
    quantity,
  ]);
  return rows[0];
}

module.exports = { createOrder };
