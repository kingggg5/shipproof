// Secure counterpart of the vulnerable corpus. Parameterized queries,
// explicit authorization middleware, and bounded rate limiting.
const express = require("express");
const helmet = require("helmet");

const app = express();

app.use(helmet());
app.use(requireAuth);
app.use(
  rateLimit({
    windowMs: 60000,
    max: 100,
    keyGenerator: (req) => req.user?.id ?? req.ip,
  })
);

app.delete("/admin/users/:id", requireAdmin, async (req, res, next) => {
  try {
    await db.removeUser(Number(req.params.id));
    res.json({ removed: true });
  } catch (error) {
    next(error);
  }
});

app.post("/orders", async (req, res, next) => {
  try {
    const order = await createOrder(req.body.productName, Number(req.body.quantity));
    res.json(order);
  } catch (error) {
    next(error);
  }
});

module.exports = app;
