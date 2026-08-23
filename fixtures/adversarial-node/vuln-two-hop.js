// Adversarial recall probe: two-hop local aliasing before a code-execution
// sink. Only the interprocedural/local taint engine can attribute this.
router.get("/search", (req, res) => {
  const a = req.query.q;
  const b = a;
  eval(b);
});
