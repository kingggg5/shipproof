// Intentionally vulnerable head-to-head corpus. Never use in an application.
//
// The request body flows through a helper into a concatenated SQL statement
// in another file, so only the cross-file taint engine (L2) can attribute it.
const { createOrder } = require("../services/order-service");

router.post("/orders", async (req, res) => {
  const order = await createOrder(req.body.productName, req.body.quantity);
  res.json(order);
});
