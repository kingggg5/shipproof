// Adversarial precision trap: a hardened Express app. Global auth middleware,
// helmet, rate limiting with keyGenerator, guarded admin routes, async wrappers.
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

module.exports = app;
