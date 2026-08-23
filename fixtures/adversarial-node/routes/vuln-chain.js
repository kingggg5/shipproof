// Adversarial recall probe: tainted value crosses two helper boundaries
// before reaching the SQL sink in a third file.
const { stepOne } = require("../services/chain");

router.get("/chain/:id", (req, res) => {
  res.send(stepOne(req.params.id));
});
