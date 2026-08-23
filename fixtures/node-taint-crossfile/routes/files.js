// Intentionally vulnerable head-to-head corpus. Never use in an application.
//
// The request parameter reaches a filesystem path and TLS verification is
// disabled for an outbound client.
const { readFileReport } = require("../utils/storage");

router.get("/files/:name", async (req, res) => {
  const contents = await readFileReport(req.params.name);
  res.send(contents);
});

const insecureClient = { rejectUnauthorized: false };
