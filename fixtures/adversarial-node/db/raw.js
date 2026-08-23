// Adversarial recall probe: terminal SQL sink of the three-file chain.
function runRaw(statement) {
  return connection.execute(statement);
}

module.exports = { runRaw };
