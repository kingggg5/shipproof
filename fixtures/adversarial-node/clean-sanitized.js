// Adversarial precision trap: everything below LOOKS vulnerable but must
// stay silent. Parameterized statements, sanitized chains, and safe DOM APIs.
const { query } = require("./db");

router.get("/users/:id", async (req, res, next) => {
  try {
    const rows = await query("SELECT * FROM users WHERE id = ?", [req.params.id]);
    res.json(rows);
  } catch (error) {
    next(error);
  }
});

function showProfile(rawName) {
  const fileName = path.basename(rawName);
  const target = path.join(DATA_DIR, fileName);
  if (!target.startsWith(DATA_DIR + path.sep)) throw new Error("bad path");
  return fs.readFileSync(target, "utf8");
}

function renderComment(dirtyHtml) {
  container.innerHTML = DOMPurify.sanitize(dirtyHtml);
}
