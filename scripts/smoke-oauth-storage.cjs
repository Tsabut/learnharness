/** Real OS credential-storage smoke, without OAuth or user credentials.
 * Run: node node_modules/electron/cli.js scripts/smoke-oauth-storage.cjs
 * Two independent Electron processes create and reopen one isolated profile.
 * A key digest stays on private IPC. Stdout distinguishes encrypted storage
 * from safe refusal when an OS key store is unavailable. No plaintext fallback.
 */
const { app, safeStorage } = require("electron");
const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { loadOrCreateOAuthKey } = require("../electron/oauth-security.cjs");

const workspace = path.resolve(__dirname, "..");
const workRoot = path.join(workspace, "work");
const probeIndex = process.argv.indexOf("--oauth-storage-probe");
const phase = probeIndex >= 0 ? process.argv[probeIndex + 1] : undefined;
const linuxBasic = process.argv.includes("--linux-basic");
const expectEncrypted = process.argv.includes("--expect-encrypted");
const expectUnavailable = process.argv.includes("--expect-unavailable");
const noSandbox = process.platform === "linux" && process.argv.includes("--no-sandbox");
// Only this no-window CI probe needs the escape hatch on Ubuntu runners
// that forbid npm Electron's user namespace. Never change a host policy.
if (noSandbox) app.commandLine.appendSwitch("no-sandbox");
const requiredStorage = expectEncrypted ? "encrypted" : expectUnavailable ? "unavailable" :
	process.platform === "linux" ? undefined : "encrypted";
const metadata = {
	ok: false, platform: process.platform, storage: "error", secureStorageAvailable: false,
	created: false, reopened: false, ciphertextProtected: false,
	crossProcessRecovered: false, unavailableFailClosed: false, isolatedProfile: false, cleaned: false,
};
let smokeRoot;

function confinedToWork(value) {
	const actual = fs.realpathSync(value);
	const root = fs.realpathSync(workRoot);
	return actual.startsWith(`${root}${path.sep}`) && path.dirname(root) === fs.realpathSync(workspace);
}

function sendProbe(value, code) {
	if (!process.connected || !process.send) return app.exit(1);
	process.send({ type: "lh:oauth-storage-smoke", ...value }, () => app.exit(code));
}

async function probe() {
	const profile = path.resolve(process.env.LH_OAUTH_STORAGE_SMOKE_PROFILE || "");
	if (!["create", "reopen"].includes(phase) || !confinedToWork(profile)) throw new Error("Invalid smoke profile");
	app.setName("LearnHarness OAuth Storage Smoke");
	app.setPath("userData", profile);
	if (linuxBasic && process.platform === "linux") app.commandLine.appendSwitch("password-store", "basic");
	await app.whenReady();
	const filename = path.join(profile, "openai-vault-key.enc");
	const existed = fs.existsSync(filename);
	if (phase === "create" && existed) throw new Error("Unexpected smoke key state");
	const key = await loadOrCreateOAuthKey({ userDataDir: profile, safeStorage });
	const isolated = confinedToWork(profile) && app.getPath("userData") === profile;
	if (key === undefined) {
		// Exercise the actual production helper against the actual Electron
		// provider. basic_text must return no key and create no vault-key file.
		const failClosed = !existed && !fs.existsSync(filename);
		sendProbe({ ok: failClosed && isolated, storage: "unavailable", available: false, existed, protectedBytes: false, isolated, failClosed }, failClosed && isolated ? 0 : 1);
		return;
	}
	const valid = typeof key === "string" && Buffer.from(key, "base64").length === 32;
	if (!valid) throw new Error("Protected key unavailable");
	const ciphertext = fs.readFileSync(filename);
	const protectedBytes = ciphertext.length > 0 &&
		!ciphertext.includes(Buffer.from(key)) && !ciphertext.includes(Buffer.from(key, "base64"));
	if (!protectedBytes || !isolated || !confinedToWork(filename)) throw new Error("Protected key invariant failed");
	const digest = createHash("sha256").update(Buffer.from(key, "base64")).digest("hex");
	sendProbe({ ok: true, storage: "encrypted", available: true, existed, protectedBytes, isolated, digest }, 0);
}

function runProbe(profile, probePhase) {
	return new Promise((resolve, reject) => {
		const env = { ...process.env, LH_OAUTH_STORAGE_SMOKE_PROFILE: profile };
		for (const name of Object.keys(env)) {
			if (["LH_OAUTH_ENCRYPTION_KEY", "ELECTRON_RUN_AS_NODE"].includes(name.toUpperCase())) delete env[name];
		}
		const child = spawn(process.execPath, [__filename, "--oauth-storage-probe", probePhase,
			...(linuxBasic ? ["--linux-basic"] : []), ...(noSandbox ? ["--no-sandbox"] : [])], {
			env, stdio: ["ignore", "ignore", "ignore", "ipc"], windowsHide: true,
		});
		let report;
		const timer = setTimeout(() => { child.kill(); reject(new Error("OS storage smoke timed out")); }, 30_000);
		child.on("message", (value) => {
			if (value && value.type === "lh:oauth-storage-smoke") report = value;
		});
		child.once("error", () => { clearTimeout(timer); reject(new Error("OS storage smoke process failed")); });
		child.once("exit", (code) => {
			clearTimeout(timer);
			if (code === 0 && report?.ok === true) resolve(report);
			else reject(new Error("OS storage smoke probe failed"));
		});
	});
}

async function main() {
	if (!["win32", "darwin", "linux"].includes(process.platform) || (expectEncrypted && expectUnavailable) ||
		(linuxBasic && process.platform !== "linux")) throw new Error("Invalid OS storage smoke configuration");
	fs.mkdirSync(workRoot, { recursive: true });
	if (path.dirname(fs.realpathSync(workRoot)) !== fs.realpathSync(workspace)) throw new Error("Invalid workspace scratch directory");
	smokeRoot = fs.mkdtempSync(path.join(workRoot, "oauth-storage-smoke-"));
	const coordinatorProfile = path.join(smokeRoot, "coordinator");
	const testProfile = path.join(smokeRoot, "profile");
	fs.mkdirSync(coordinatorProfile);
	fs.mkdirSync(testProfile);
	app.setName("LearnHarness OAuth Storage Smoke Coordinator");
	app.setPath("userData", coordinatorProfile);
	await app.whenReady();
	const created = await runProbe(testProfile, "create");
	metadata.secureStorageAvailable = created.available === true;
	const reopened = await runProbe(testProfile, "reopen");
	if (created.storage !== reopened.storage) throw new Error("OS storage availability changed between processes");
	metadata.storage = created.storage;
	metadata.created = created.storage === "encrypted" && created.existed === false;
	metadata.reopened = reopened.storage === "encrypted" && reopened.existed === true;
	metadata.ciphertextProtected = created.protectedBytes === true && reopened.protectedBytes === true;
	metadata.crossProcessRecovered = typeof created.digest === "string" && created.digest === reopened.digest;
	metadata.unavailableFailClosed = created.storage === "unavailable" && created.failClosed === true && reopened.failClosed === true;
	metadata.isolatedProfile = created.isolated === true && reopened.isolated === true;
}

if (phase) {
	void probe().catch(() => sendProbe({ ok: false }, 1));
} else {
	void main().catch(() => { /* Only boolean outcomes leave this process. */ }).finally(() => {
		try {
			// Check the resolved absolute target before recursively removing it.
			if (smokeRoot && confinedToWork(smokeRoot) && /^oauth-storage-smoke-[A-Za-z0-9]+$/.test(path.basename(smokeRoot))) {
				fs.rmSync(fs.realpathSync(smokeRoot), { recursive: true, force: true });
				metadata.cleaned = !fs.existsSync(smokeRoot);
			}
		} catch { /* A failed cleanup makes the smoke fail, without touching another path. */ }
		const encrypted = metadata.storage === "encrypted" && metadata.secureStorageAvailable && metadata.created &&
			metadata.reopened && metadata.ciphertextProtected && metadata.crossProcessRecovered;
		const unavailable = metadata.storage === "unavailable" && metadata.unavailableFailClosed && !metadata.secureStorageAvailable;
		metadata.ok = metadata.cleaned && metadata.isolatedProfile &&
			(!requiredStorage || metadata.storage === requiredStorage) && (encrypted || unavailable);
		console.log(JSON.stringify(metadata));
		app.exit(metadata.ok ? 0 : 1);
	});
}
