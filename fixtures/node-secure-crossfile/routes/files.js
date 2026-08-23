// Secure counterpart of the vulnerable corpus. The file name is reduced to
// its base component and wrapped in error handling before any filesystem use.
const path = require("path");
const { readFileReport } = require("../utils/storage");

router.get("/files/:name", async (req, res, next) => {
  try {
    const contents = await readFileReport(path.basename(req.params.name));
    res.send(contents);
  } catch (error) {
    next(error);
  }
});
