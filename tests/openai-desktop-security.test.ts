import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, it } from "node:test";
import {
	configureUserData, childDataPaths, loadOrCreateOAuthKey, oauthChildEnvironment,
	isAllowedOAuthURL, attachOAuthBrowserIPC,
} from "../electron/oauth-security.cjs";

// An injected OS adapter uses authenticated encryption in Node. These tests
// exercise storage and transport boundaries without claiming to test DPAPI.
function protectedStorage() {
	const machineKey = randomBytes(32);
	return {
		available: true,
		rotate: false,
		async isAsyncEncryptionAvailable() { return this.available; },
		async encryptStringAsync(value: string) {
			const nonce = randomBytes(12);
			const cipher = createCipheriv("aes-256-gcm", machineKey, nonce);
			return Buffer.concat([nonce, cipher.update(value, "utf8"), cipher.final(), cipher.getAuthTag()]);
		},
		async decryptStringAsync(value: Buffer) {
			const decipher = createDecipheriv("aes-256-gcm", machineKey, value.subarray(0, 12));
			decipher.setAuthTag(value.subarray(-16));
			return {
				result: Buffer.concat([decipher.update(value.subarray(12, -16)), decipher.final()]).toString("utf8"),
				shouldReEncrypt: this.rotate,
			};
		},
		getSelectedStorageBackend() { return "gnome_libsecret"; },
	};
}

async function withProfile(run: (dir: string) => Promise<void>) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lh-oauth-desktop-"));
	try { await run(dir); }
	finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

describe("desktop OAuth protected key bootstrap", () => {
	it("persists only encrypted bytes and recovers the same 256-bit key after restart", async () => {
		await withProfile(async (userDataDir) => {
			const safeStorage = protectedStorage();
			const key = await loadOrCreateOAuthKey({ userDataDir, safeStorage, platform: "win32" });
			assert.ok(key);
			assert.equal(Buffer.from(key, "base64").length, 32);
			const file = path.join(userDataDir, "openai-vault-key.enc");
			const encrypted = fs.readFileSync(file);
			assert.equal(encrypted.includes(Buffer.from(key)), false);
			assert.equal(encrypted.includes(Buffer.from(key, "base64")), false);
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage, platform: "win32" }), key);
			assert.deepEqual(fs.readdirSync(userDataDir), ["openai-vault-key.enc"]);
		});
	});

	it("fails closed without creating a key when secure storage is unavailable", async () => {
		await withProfile(async (userDataDir) => {
			const safeStorage = protectedStorage();
			safeStorage.available = false;
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage, platform: "win32" }), undefined);
			assert.deepEqual(fs.readdirSync(userDataDir), []);
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage: {
				...safeStorage, available: true,
				encryptStringAsync: async () => { throw new Error("OS provider unavailable"); },
			}, platform: "win32" }), undefined);
			assert.deepEqual(fs.readdirSync(userDataDir), []);
		});
	});

	it("preserves unreadable existing ciphertext instead of replacing a vault's key", async () => {
		await withProfile(async (userDataDir) => {
			const file = path.join(userDataDir, "openai-vault-key.enc");
			const corrupted = Buffer.from("not a valid protected key");
			fs.writeFileSync(file, corrupted);
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage: protectedStorage(), platform: "win32" }), undefined);
			assert.deepEqual(fs.readFileSync(file), corrupted);
		});
	});

	it("rejects plaintext fallback and malformed decrypted keys", async () => {
		await withProfile(async (userDataDir) => {
			const safeStorage = protectedStorage();
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage: {
				...safeStorage, encryptStringAsync: async (value: string) => Buffer.from(value),
			}, platform: "win32" }), undefined);
			assert.deepEqual(fs.readdirSync(userDataDir), []);
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage: {
				...safeStorage, getSelectedStorageBackend: () => "basic_text",
			}, platform: "linux" }), undefined);
			fs.writeFileSync(path.join(userDataDir, "openai-vault-key.enc"), "encrypted-invalid-key");
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage: {
				...safeStorage, decryptStringAsync: async () => ({ result: "short", shouldReEncrypt: false }),
			}, platform: "win32" }), undefined);
		});
	});

	it("re-encrypts after OS key rotation while retaining the vault key", async () => {
		await withProfile(async (userDataDir) => {
			const safeStorage = protectedStorage();
			const key = await loadOrCreateOAuthKey({ userDataDir, safeStorage, platform: "win32" });
			const file = path.join(userDataDir, "openai-vault-key.enc");
			const before = fs.readFileSync(file);
			safeStorage.rotate = true;
			assert.equal(await loadOrCreateOAuthKey({ userDataDir, safeStorage, platform: "win32" }), key);
			assert.notDeepEqual(fs.readFileSync(file), before);
			assert.deepEqual(fs.readdirSync(userDataDir), ["openai-vault-key.enc"]);
		});
	});

	it("injects only a validated protected key and drops inherited case variants on failure", () => {
		const env = { LH_OAUTH_ENCRYPTION_KEY: "inherited", lh_oauth_encryption_key: "inherited-too", API_KEY: "preserved" };
		assert.deepEqual(oauthChildEnvironment(env, undefined), { API_KEY: "preserved" });
		assert.deepEqual(oauthChildEnvironment(env, "invalid"), { API_KEY: "preserved" });
		const key = randomBytes(32).toString("base64");
		assert.deepEqual(oauthChildEnvironment(env, key), { API_KEY: "preserved", LH_OAUTH_ENCRYPTION_KEY: key });
		assert.equal(env.LH_OAUTH_ENCRYPTION_KEY, "inherited", "mutated parent environment");
	});
});

describe("desktop OAuth browser boundary", () => {
	const authorizationURL = "https://auth.openai.com/api/accounts/authorize?client_id=test&state=secret&redirect_uri=http%3A%2F%2Flocalhost%3A5555%2Fcallback";
	it("allows the exact HTTPS endpoint while rejecting unsafe or ambiguous URLs", () => {
		assert.equal(isAllowedOAuthURL(authorizationURL), true);
		assert.equal(isAllowedOAuthURL("https://auth.openai.com/api/accounts/authorize"), true);
		for (const url of [
			"http://auth.openai.com/api/accounts/authorize", "file:///C:/Windows/system32/calc.exe",
			"https://auth.openai.com.evil.example/api/accounts/authorize", "https://evil.example/api/accounts/authorize",
			"https://auth.openai.com:443/api/accounts/authorize", "https://auth.openai.com:8443/api/accounts/authorize",
			"https://user:secret@auth.openai.com/api/accounts/authorize", "https://auth.openai.com/api/accounts/authorize/",
			"https://auth.openai.com/api/accounts/authorize#secret", "https://auth.openai.com/api/accounts/token",
			" https://auth.openai.com/api/accounts/authorize", "https://auth.openai.com\\api/accounts/authorize",
			"https://auth.openai.com/api/accounts/authorize\n", "https://auth.openai.com/api/accounts/authorize?x=" + "x".repeat(2081),
			undefined, {},
		]) assert.equal(isAllowedOAuthURL(url), false, `accepted ${String(url)}`);
	});

	it("acknowledges browser success/failure on private child IPC without echoing URLs", async () => {
		class Child extends EventEmitter {
			connected = true;
			send(message: unknown, callback: () => void) { this.emit("reply", message); callback(); }
		}
		const child = new Child();
		const opened: string[] = [];
		let fail = false;
		const detach = attachOAuthBrowserIPC(child, async (url: string) => {
			opened.push(url);
			if (fail) throw new Error("sensitive URL could be in an OS error");
		});
		const send = (url: string, id: string) => new Promise((resolve) => {
			child.once("reply", resolve);
			child.emit("message", { type: "lh:oauth-open", id, url });
		});
		assert.deepEqual(await send(authorizationURL, "success"), { type: "lh:oauth-open-result", id: "success", ok: true });
		assert.deepEqual(await send("file:///C:/sensitive", "unsafe"), { type: "lh:oauth-open-result", id: "unsafe", ok: false });
		assert.equal(opened.length, 1);
		fail = true;
		assert.deepEqual(await send(authorizationURL, "failed"), { type: "lh:oauth-open-result", id: "failed", ok: false });
		assert.equal(opened.length, 2);
		child.emit("message", { type: "other", id: "ignored", url: authorizationURL });
		assert.equal(opened.length, 2);
		detach();
		assert.equal(child.listenerCount("message"), 0);
	});
});

describe("isolated desktop profile paths", () => {
	it("creates and selects the absolute explicit profile before the lock, even in dev mode", async () => {
		await withProfile(async (dir) => {
			const installed = path.join(dir, "installed-app-profile");
			const isolated = path.join(dir, "separate", "smoke-profile");
			const app = {
				getPath: () => installed,
				setPath(name: string, value: string) {
					assert.equal(name, "userData");
					assert.equal(value, isolated);
					assert.ok(fs.statSync(value).isDirectory(), "profile was not created before Electron received it");
				},
			};
			const relative = path.relative(process.cwd(), isolated);
			assert.equal(configureUserData(app, { LH_USER_DATA_DIR: relative, LH_DEV_URL: "http://localhost:3000" }), isolated);
			assert.equal(fs.existsSync(installed), false, "touched the installed profile");
		});
	});

	it("resolves test data/auth overrides before the server changes cwd and preserves defaults", () => {
		const profile = path.resolve("work", "test-profile");
		assert.deepEqual(childDataPaths(profile, {}), {
			dataDir: path.join(profile, "data"), authFile: path.join(profile, "auth.json"),
		});
		assert.deepEqual(childDataPaths(profile, { LH_DATA_DIR: "work/test-data", LH_AUTH_FILE: "work/test-auth.json" }), {
			dataDir: path.resolve("work/test-data"), authFile: path.resolve("work/test-auth.json"),
		});
	});
});
