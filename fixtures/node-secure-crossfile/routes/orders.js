// Secure counterpart of the vulnerable corpus. The tainted body value only
// reaches a parameterized query through the service helper.
const { createOrder } = require("../services/order-service");

router.post("/orders", async (req, res, next) => {
  try {
    const order = await createOrder(req.body.productName, Number(req.body.quantity));
    res.json(order);
  } catch (error) {
    next(error);
  }
});
