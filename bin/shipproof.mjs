#!/usr/bin/env node

import { runCli } from "../lib/cli.mjs";

process.exitCode = runCli(process.argv.slice(2));
