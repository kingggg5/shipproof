// Adversarial recall probe: middle of a three-file taint chain.
const { runRaw } = require("../db/raw");

function stepOne(value) {
  return runRaw("SELECT * FROM items WHERE id = '" + value + "'");
}

module.exports = { stepOne };
