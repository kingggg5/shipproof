// Intentionally vulnerable head-to-head corpus. Never use in an application.
//
// The raw file name is joined into a filesystem path without validation.
async function readFileReport(rawName) {
  const reportPath = path.join(__dirname, "../reports/" + rawName);
  return fs.readFile(reportPath, "utf8");
}

module.exports = { readFileReport };
