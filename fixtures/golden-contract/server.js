// Golden contract fixture: deterministic Express findings for compatibility tests.
const express = require("express");

const app = express();

app.post("/api/auth/login", signIn);

app.listen(3000);
