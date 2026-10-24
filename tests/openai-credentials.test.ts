import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { createOpenAICredentials, OpenAICredentialStorageError, type OpenAIOAuthCredential } from "../src/store/openai-credentials.ts";

const credential: OpenAIOAuthCredential = { type: "oauth", access: "secret-access", refresh: "secret-refresh", expires: 12345678900000, idToken: "secret-id-token", clientId: "oaiapp_test", scopes: ["chatgpt.tokens.use.direct"], issuer: "https://auth.openai.com", subject: "subject-test", email: "private@example.test" };

function fixture() {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lh-oauth-store-"));
	const encryptionKey = randomBytes(32);
	return { directory, encryptionKey, store: createOpenAICredentials({ directory, encryptionKey }), cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
}

test("vault encrypts all identity and token data, survives restart, and rejects tampering or the wrong OS key", async () => {
	const f = fixture();
	try {
		await f.store.transaction((state) => { state.mode = "oauth"; state.activeAccountId = "account-a"; state.accounts.push({ id: "account-a", clientId: credential.clientId, issuer: credential.issuer, subject: credential.subject, credential }); });
		const serialized = fs.readFileSync(path.join(f.directory, "vault.enc"), "utf8");
		for (const secret of [credential.access, credential.refresh, credential.idToken, credential.subject, credential.email!]) assert.ok(!serialized.includes(secret));
		const restarted = createOpenAICredentials(f);
		assert.deepEqual(restarted.readState(), f.store.readState());
		assert.throws(() => createOpenAICredentials({ directory: f.directory, encryptionKey: randomBytes(32) }).readState(), OpenAICredentialStorageError);
		const envelope = JSON.parse(serialized);
		envelope.tag = randomBytes(16).toString("base64");
		fs.writeFileSync(path.join(f.directory, "vault.enc"), JSON.stringify(envelope));
		assert.throws(() => restarted.readState(), OpenAICredentialStorageError);
		assert.ok(fs.existsSync(path.join(f.directory, "vault.enc")), "corrupt vault is preserved");
	} finally { f.cleanup(); }
});

test("installation ID persists across stores and log-out retains registration while removing credentials", async () => {
	const f = fixture();
	try {
		const first = f.store.readState().installationId;
		assert.equal((await f.store.ensure()).installationId, first);
		assert.equal(createOpenAICredentials(f).readState().installationId, first);
		await f.store.transaction((state) => {
			state.accounts.push({ id: "a", clientId: credential.clientId, issuer: credential.issuer, subject: credential.subject, credential: structuredClone(credential) });
			state.accounts.push({ id: "b", clientId: "oaiapp_other", issuer: credential.issuer, subject: "subject-other", email: credential.email });
			state.activeAccountId = "a"; state.mode = "oauth";
		});
		await f.store.transaction((state) => { delete state.accounts[0]!.credential; });
		const after = createOpenAICredentials(f).readState();
		assert.equal(after.accounts.length, 2);
		assert.equal(after.accounts[0]!.clientId, credential.clientId);
		assert.equal(after.accounts[0]!.subject, credential.subject);
		assert.equal(after.accounts[0]!.credential, undefined);
		assert.equal(after.installationId, first);
	} finally { f.cleanup(); }
});

test("concurrent asynchronous transactions serialize rotation and do not discard a rotation when its caller cancels", async () => {
	const f = fixture();
	try {
		await f.store.transaction((state) => { state.accounts.push({ id: "a", clientId: credential.clientId, issuer: credential.issuer, subject: credential.subject, credential: structuredClone(credential) }); });
		const other = createOpenAICredentials(f);
		let rotations = 0;
		const abort = new AbortController();
		const rotate = (store: typeof f.store, signal?: AbortSignal) => store.transaction(async (state) => {
			const current = state.accounts[0]!.credential!;
			if (current.refresh !== "secret-refresh") return;
			rotations++;
			await delay(40);
			abort.abort();
			current.access = "replacement-access"; current.refresh = "replacement-refresh";
		}, { signal });
		await Promise.all([rotate(f.store, abort.signal), rotate(other)]);
		assert.equal(rotations, 1);
		assert.equal(other.readState().accounts[0]!.credential!.refresh, "replacement-refresh");
		assert.deepEqual(fs.readdirSync(f.directory), ["vault.enc"]);
	} finally { f.cleanup(); }
});

test("separate server processes cannot race a rotating refresh token", async () => {
	const f = fixture();
	try {
		await f.store.transaction((state) => { state.accounts.push({ id: "a", clientId: credential.clientId, issuer: credential.issuer, subject: credential.subject, credential: structuredClone(credential) }); });
		const moduleUrl = pathToFileURL(path.resolve("src/store/openai-credentials.ts")).href;
		const script = `import {createOpenAICredentials} from ${JSON.stringify(moduleUrl)}; const store=createOpenAICredentials({directory:process.env.LH_TEST_VAULT,encryptionKey:process.env.LH_TEST_VAULT_KEY}); await store.transaction(async state=>{const c=state.accounts[0].credential;if(c.refresh!=="secret-refresh")return;await new Promise(r=>setTimeout(r,60));c.refresh="rotated-once";c.access="new-access";});`;
		const run = () => new Promise<void>((resolve, reject) => {
			const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], { env: { ...process.env, LH_TEST_VAULT: f.directory, LH_TEST_VAULT_KEY: f.encryptionKey.toString("base64") }, stdio: ["ignore", "ignore", "pipe"] });
			let error = ""; child.stderr.on("data", (chunk) => { error += String(chunk); });
			child.once("error", reject); child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(error)));
		});
		await Promise.all([run(), run()]);
		assert.equal(f.store.readState().accounts[0]!.credential!.refresh, "rotated-once");
	} finally { f.cleanup(); }
});

test("stale-lock reclamation cannot remove a replacement lock acquired by another cleaner", async () => {
	const f = fixture();
	const originalRead = fs.readFileSync;
	let other: Promise<void> | undefined;
	let otherActive = false;
	let enteredWhileOtherActive = false;
	try {
		await f.store.ensure();
		const lock = path.join(f.directory, "vault.lock");
		const owner = path.join(lock, "owner.json");
		fs.mkdirSync(lock);
		fs.writeFileSync(owner, JSON.stringify({ pid: 2147483647, id: "dead-owner" }));
		let armed = true;
		// A reads the dead owner. Before A can remove it, B runs an actual
		// competing store transaction. Previously B could replace the lock
		// and A would then unlink B's live owner from its stale snapshot.
		fs.readFileSync = ((filename: fs.PathOrFileDescriptor, ...args: unknown[]) => {
			const value = Reflect.apply(originalRead, fs, [filename, ...args]);
			if (armed && filename === owner) {
				armed = false;
				other = createOpenAICredentials(f).transaction(async () => { otherActive = true; await delay(100); otherActive = false; });
			}
			return value;
		}) as typeof fs.readFileSync;
		await f.store.transaction(() => { enteredWhileOtherActive = otherActive; });
		assert.equal(armed, false, "the adversarial interleaving was exercised");
		assert.equal(enteredWhileOtherActive, false, "only one rotating-token mutation may own the vault");
		await other;
		assert.deepEqual(fs.readdirSync(f.directory), ["vault.enc"]);
	} finally { fs.readFileSync = originalRead; await other; f.cleanup(); }
});

test("an interrupted reclamation guard fails closed rather than being unsafely auto-broken", async () => {
	const f = fixture();
	try {
		await f.store.ensure();
		const lock = path.join(f.directory, "vault.lock");
		fs.mkdirSync(lock);
		fs.writeFileSync(path.join(lock, "owner.json"), JSON.stringify({ pid: 2147483647, id: "dead-owner" }));
		fs.writeFileSync(path.join(f.directory, "vault.recovery"), JSON.stringify({ pid: 2147483647 }));
		let mutated = false;
		await assert.rejects(f.store.transaction(() => { mutated = true; }, { signal: AbortSignal.timeout(75) }));
		assert.equal(mutated, false);
		assert.equal(fs.existsSync(path.join(f.directory, "vault.enc")), true);
		assert.equal(fs.existsSync(path.join(f.directory, "vault.recovery")), true);
	} finally { f.cleanup(); }
});

test("failed mutations preserve the encrypted record and missing key fails closed", async () => {
	const f = fixture();
	try {
		await f.store.ensure();
		const before = fs.readFileSync(path.join(f.directory, "vault.enc"), "utf8");
		await assert.rejects(f.store.transaction((state) => { state.mode = "oauth"; throw new Error("failed exchange"); }), /failed exchange/);
		assert.equal(fs.readFileSync(path.join(f.directory, "vault.enc"), "utf8"), before);
		const previous = process.env.LH_OAUTH_ENCRYPTION_KEY;
		delete process.env.LH_OAUTH_ENCRYPTION_KEY;
		try {
			const locked = createOpenAICredentials({ directory: f.directory });
			assert.throws(() => locked.readState(), OpenAICredentialStorageError);
			await assert.rejects(locked.ensure(), OpenAICredentialStorageError);
		} finally { if (previous === undefined) delete process.env.LH_OAUTH_ENCRYPTION_KEY; else process.env.LH_OAUTH_ENCRYPTION_KEY = previous; }
	} finally { f.cleanup(); }
});
