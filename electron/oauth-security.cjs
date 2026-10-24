// Main-process-only OAuth plumbing. Keeping Electron injected makes the
// security boundary testable in Node without importing a renderer bridge.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const KEY_FILE = "openai-vault-key.enc";
const KEY_ENV = "LH_OAUTH_ENCRYPTION_KEY";

/**
 * Apply an explicit test profile before taking Electron's instance lock.
 * @param {object} app
 * @param {Record<string, string | undefined>} [env]
 */
function configureUserData(app, env = process.env) {
	const userDataDir = path.resolve(env.LH_USER_DATA_DIR ||
		`${app.getPath("userData")}${env.LH_DEV_URL ? "-dev" : ""}`);
	fs.mkdirSync(userDataDir, { recursive: true, mode: 0o700 });
	app.setPath("userData", userDataDir);
	return userDataDir;
}

/**
 * Resolve overrides before the child changes cwd to its packaged server.
 * @param {string} userDataDir
 * @param {Record<string, string | undefined>} [env]
 */
function childDataPaths(userDataDir, env = process.env) {
	return {
		dataDir: path.resolve(env.LH_DATA_DIR || path.join(userDataDir, "data")),
		authFile: path.resolve(env.LH_AUTH_FILE || path.join(userDataDir, "auth.json")),
	};
}

function validKey(value) {
	return typeof value === "string" && /^[A-Za-z0-9+/]{43}=$/.test(value) &&
		Buffer.from(value, "base64").length === 32;
}

async function writeEncryptedKey(file, encrypted) {
	if (!Buffer.isBuffer(encrypted) || encrypted.length === 0) throw new Error("Invalid encrypted key");
	const temporary = `${file}.${crypto.randomUUID()}.tmp`;
	let handle;
	try {
		handle = await fs.promises.open(temporary, "wx", 0o600);
		await handle.writeFile(encrypted);
		await handle.sync();
		await handle.close();
		handle = undefined;
		await fs.promises.rename(temporary, file);
	} finally {
		await handle?.close().catch(() => {});
		await fs.promises.unlink(temporary).catch(() => {});
	}
}

async function encryptKey(safeStorage, key) {
	const encrypted = await safeStorage.encryptStringAsync(key);
	if (!Buffer.isBuffer(encrypted) || encrypted.length === 0 ||
		encrypted.includes(Buffer.from(key)) || encrypted.includes(Buffer.from(key, "base64"))) {
		throw new Error("OS key protection failed");
	}
	return encrypted;
}

/**
 * Called only after app.whenReady(). Windows safeStorage uses DPAPI. The
 * single-instance lock owns this file; no key is ever written as plaintext.
 * A missing/unavailable key disables OAuth without preventing BYOK startup.
 * @param {{userDataDir: string, safeStorage: object, platform?: string}} options
 * @returns {Promise<string | undefined>}
 */
async function loadOrCreateOAuthKey({ userDataDir, safeStorage, platform = process.platform }) {
	try {
		// Linux's basic_text backend uses a hardcoded password; never accept it.
		if (platform === "linux" && (!safeStorage.getSelectedStorageBackend ||
			["basic_text", "unknown"].includes(safeStorage.getSelectedStorageBackend()))) return undefined;
		if (!await safeStorage.isAsyncEncryptionAvailable()) return undefined;
		const file = path.join(userDataDir, KEY_FILE);
		let encrypted;
		try { encrypted = await fs.promises.readFile(file); }
		catch (error) { if (error.code !== "ENOENT") throw error; }
		if (encrypted) {
			const decrypted = await safeStorage.decryptStringAsync(encrypted);
			if (!validKey(decrypted.result)) return undefined;
			if (decrypted.shouldReEncrypt) {
				await writeEncryptedKey(file, await encryptKey(safeStorage, decrypted.result));
			}
			return decrypted.result;
		}
		const key = crypto.randomBytes(32).toString("base64");
		const protectedKey = await encryptKey(safeStorage, key);
		await fs.promises.mkdir(userDataDir, { recursive: true, mode: 0o700 });
		await writeEncryptedKey(file, protectedKey);
		return key;
	} catch {
		// Do not log the exception: OS crypto errors may include secret material.
		return undefined;
	}
}

/** Never inherit an externally supplied key when protected storage failed. */
function oauthChildEnvironment(env, key) {
	const childEnv = { ...env };
	for (const name of Object.keys(childEnv)) {
		if (name.toUpperCase() === KEY_ENV) delete childEnv[name];
	}
	if (validKey(key)) childEnv[KEY_ENV] = key;
	return childEnv;
}

/** Only the exact authorization endpoint may leave the private child IPC. */
function isAllowedOAuthURL(value) {
	if (typeof value !== "string" || value.length > 2081 || /[\s\\#]/.test(value) ||
		!/^https:\/\/auth\.openai\.com\/api\/accounts\/authorize(?:\?|$)/.test(value)) return false;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && url.hostname === "auth.openai.com" &&
			url.pathname === "/api/accounts/authorize" && !url.port &&
			!url.username && !url.password && !url.hash;
	} catch { return false; }
}

/**
 * This handler is attached only to the process spawned by the main process.
 * No ipcMain/renderer handler accepts arbitrary browser URLs or credentials.
 */
function attachOAuthBrowserIPC(child, openExternal) {
	const pending = new Set();
	const onMessage = async (message) => {
		if (!message || message.type !== "lh:oauth-open" ||
			typeof message.id !== "string" || !/^[A-Za-z0-9-]{1,128}$/.test(message.id) ||
			pending.has(message.id)) return;
		pending.add(message.id);
		let ok = false;
		try {
			if (isAllowedOAuthURL(message.url)) {
				await openExternal(message.url);
				ok = true;
			}
		} catch { /* Return only a boolean; never send/log the sensitive URL. */ }
		finally {
			pending.delete(message.id);
			if (child.connected) {
				try { child.send({ type: "lh:oauth-open-result", id: message.id, ok }, () => {}); }
				catch { /* Server exited while the browser was opening. */ }
			}
		}
	};
	child.on("message", onMessage);
	return () => child.off("message", onMessage);
}

module.exports = {
	configureUserData, childDataPaths, loadOrCreateOAuthKey, oauthChildEnvironment,
	isAllowedOAuthURL, attachOAuthBrowserIPC,
};
