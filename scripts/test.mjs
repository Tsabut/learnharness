// A shell-independent test entry point: Windows cmd does not support VAR=value prefixes.
import { spawn } from "node:child_process";

const env = { ...process.env, NODE_ENV: "test" };
for (const name of Object.keys(env)) if (name.toUpperCase() === "LH_OAUTH_ENCRYPTION_KEY") delete env[name];
const child = spawn(process.execPath, ["--import", "tsx", "--test", "--test-concurrency=2", "tests/*.test.ts", "tests/*.test.tsx", ...process.argv.slice(2)], { stdio: "inherit", env });
child.on("error", () => { process.exitCode = 1; });
child.on("exit", (code) => { process.exitCode = code ?? 1; });
