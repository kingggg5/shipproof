// Secure counterpart of the vulnerable corpus. The resolved path must stay
// inside the reports directory before any read happens.
const path = require("path");

const REPORTS_DIR = path.resolve(__dirname, "../reports");

async function readFileReport(fileName) {
  const reportPath = path.join(REPORTS_DIR, fileName);
  if (!reportPath.startsWith(REPORTS_DIR + path.sep)) {
    throw new Error("report path outside reports directory");
  }
  return fs.readFile(reportPath, "utf8");
}

module.exports = { readFileReport };
