// Adversarial precision trap: vulnerable-looking code exists ONLY inside
// comments and string literals. Executable lines are boring.
//
// const preTax = eval(req.body.preTax);
// db.query(`SELECT * FROM users WHERE name = '${name}'`);
// child_process.exec(`ls ${dir}`);
// el.innerHTML = location.hash.slice(1);
// _.merge(config, req.body);

const exampleSql = "db.execute('SELECT * FROM users WHERE id = ' + userId)";
module.exports = { exampleSql };
