// Adversarial recall probe: destructured request param into a filesystem sink.
router.get("/download", (req, res) => {
  const { file } = req.params;
  fs.readFile(path.join(DATA_DIR, file), "utf8", (err, data) => {
    if (err) res.sendStatus(404);
    else res.send(data);
  });
});
