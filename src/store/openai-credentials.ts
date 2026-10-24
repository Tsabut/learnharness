import fs from "node:fs";
import path from "node:path";
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { OAuthCredential } from "@earendil-works/pi-ai";

/** These records stay server-side. Public status must explicitly select safe fields. */
export interface OpenAIOAuthCredential extends OAuthCredential {
	clientId: string;
	scopes: string[];
	idToken: string;
	issuer: string;
	subject: string;
	email?: string;
}

export interface OpenAIAccount {
	id: string;
	clientId: string;
	issuer?: string;
	subject?: string;
	email?: string;
	planUsageAcknowledged?: boolean;
	credential?: OpenAIOAuthCredential;
}

export interface OpenAIAuthState {
	version: 1;
	installationId: string;
	mode: "api_key" | "oauth";
	activeAccountId?: string;
	accounts: OpenAIAccount[];
}

export interface OpenAICredentials {
	readState(): OpenAIAuthState;
	ensure(): Promise<OpenAIAuthState>;
	/** The lock covers the asynchronous callback AND the atomic durable write. */
	transaction<T>(mutate: (state: OpenAIAuthState) => T | Promise<T>, options?: { signal?: AbortSignal }): Promise<T>;
}

const AAD = Buffer.from("learnharness.openai-auth.v1");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class OpenAICredentialStorageError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "OpenAICredentialStorageError";
	}
}

function errorCode(error: unknown): string | undefined {
	return error && typeof error === "object" && "code" in error ? String(error.code) : undefined;
}

function validateState(value: unknown): asserts value is OpenAIAuthState {
	if (!value || typeof value !== "object") throw new Error("invalid state");
	const state = value as OpenAIAuthState;
	if (state.version !== 1 || !UUID.test(state.installationId) ||
		!["api_key", "oauth"].includes(state.mode) || !Array.isArray(state.accounts)) throw new Error("invalid state");
	const ids = new Set<string>();
	for (const account of state.accounts) {
		if (!account || typeof account.id !== "string" || !account.id || ids.has(account.id) ||
			typeof account.clientId !== "string" || !account.clientId || account.clientId === "dynamic_agent_client") throw new Error("invalid account");
		ids.add(account.id);
		if (account.planUsageAcknowledged !== undefined && typeof account.planUsageAcknowledged !== "boolean") throw new Error("invalid plan notice acknowledgement");
		for (const field of ["issuer", "subject", "email"] as const) {
			if (account[field] !== undefined && typeof account[field] !== "string") throw new Error("invalid identity");
		}
		const credential = account.credential;
		if (credential && (credential.type !== "oauth" || credential.clientId !== account.clientId ||
			typeof credential.access !== "string" || !credential.access ||
			typeof credential.refresh !== "string" || !credential.refresh ||
			typeof credential.idToken !== "string" || !credential.idToken ||
			typeof credential.expires !== "number" || !Number.isFinite(credential.expires) ||
			typeof credential.issuer !== "string" || !credential.issuer ||
			typeof credential.subject !== "string" || !credential.subject ||
			!Array.isArray(credential.scopes) || !credential.scopes.every((scope) => typeof scope === "string") ||
			account.issuer !== credential.issuer || account.subject !== credential.subject)) throw new Error("invalid credential");
	}
	if (state.activeAccountId !== undefined && !ids.has(state.activeAccountId)) throw new Error("invalid active account");
}

/** AES key is unwrapped by Electron's OS-protected safeStorage and supplied only to its server child. */
export function createOpenAICredentials(options: { directory: string; encryptionKey?: string | Buffer }): OpenAICredentials {
	const directory = path.resolve(options.directory);
	const filename = path.join(directory, "vault.enc");
	const lockPath = path.join(directory, "vault.lock");
	const recoveryPath = path.join(directory, "vault.recovery");
	const suppliedKey = options.encryptionKey ?? process.env.LH_OAUTH_ENCRYPTION_KEY;
	const key = suppliedKey === undefined ? undefined : Buffer.isBuffer(suppliedKey) ? Buffer.from(suppliedKey) : Buffer.from(suppliedKey, "base64");
	if (key && key.byteLength !== 32) throw new OpenAICredentialStorageError("ChatGPT credential encryption requires a 32-byte key.");
	const seed: OpenAIAuthState = { version: 1, installationId: randomUUID(), mode: "api_key", accounts: [] };
	let cache: { stamp: string; state: OpenAIAuthState } | undefined;
	function requireKey(): Buffer {
		if (!key) throw new OpenAICredentialStorageError("Protected ChatGPT storage is unavailable. Launch the desktop app to enable secure sign-in.");
		return key;
	}
	function readState(): OpenAIAuthState {
		try {
			const stat = fs.statSync(filename, { bigint: true });
			const stamp = `${stat.mtimeNs}:${stat.ctimeNs}:${stat.size}`;
			if (cache?.stamp === stamp) return structuredClone(cache.state);
			const encryptionKey = requireKey();
			const envelope = JSON.parse(fs.readFileSync(filename, "utf8"));
			if (envelope.version !== 1 || envelope.algorithm !== "aes-256-gcm") throw new Error("invalid envelope");
			const iv = Buffer.from(envelope.iv, "base64");
			const tag = Buffer.from(envelope.tag, "base64");
			if (iv.length !== 12 || tag.length !== 16) throw new Error("invalid envelope");
			const decipher = createDecipheriv("aes-256-gcm", encryptionKey, iv);
			decipher.setAAD(AAD);
			decipher.setAuthTag(tag);
			const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]);
			const state: unknown = JSON.parse(plaintext.toString("utf8"));
			validateState(state);
			cache = { stamp, state };
			return structuredClone(state);
		} catch (error) {
			if (errorCode(error) === "ENOENT") { cache = undefined; return structuredClone(seed); }
			if (error instanceof OpenAICredentialStorageError) throw error;
			throw new OpenAICredentialStorageError("ChatGPT credentials could not be decrypted or read. The saved vault has been preserved.");
		}
	}
	function writeState(state: OpenAIAuthState): void {
		validateState(state);
		const iv = randomBytes(12);
		const actualCipher = createCipheriv("aes-256-gcm", requireKey(), iv);
		actualCipher.setAAD(AAD);
		const ciphertext = Buffer.concat([actualCipher.update(JSON.stringify(state), "utf8"), actualCipher.final()]);
		const envelope = { version: 1, algorithm: "aes-256-gcm", iv: iv.toString("base64"), tag: actualCipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
		const temporary = path.join(directory, `.vault-${process.pid}-${randomUUID()}.tmp`);
		try {
			const fd = fs.openSync(temporary, "wx", 0o600);
			try { fs.writeFileSync(fd, JSON.stringify(envelope)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
			fs.chmodSync(temporary, 0o600);
			fs.renameSync(temporary, filename);
			cache = undefined;
		} finally {
			try { fs.unlinkSync(temporary); } catch (error) { if (errorCode(error) !== "ENOENT") throw error; }
		}
	}
	function removeAbandonedLock(): void {
		// Serialize stale-owner inspection and removal. Without this guard a
		// second cleaner can replace the stale lock after our inspection, and
		// we would unlink the replacement owner's live rotating-token lock.
		// Never auto-break this guard: recursively reclaiming it recreates the
		// same race. A crash here leaves an offline, fail-closed recovery step.
		let recovery: number;
		try { recovery = fs.openSync(recoveryPath, "wx", 0o600); }
		catch { return; }
		try {
			fs.writeFileSync(recovery, JSON.stringify({ pid: process.pid }));
			let owner: { pid: number };
			try { owner = JSON.parse(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8")); }
			catch {
				if (Date.now() - fs.statSync(lockPath).mtimeMs < 30_000) return;
				try { fs.rmdirSync(lockPath); } catch { /* another process acquired it */ }
				return;
			}
			if (!Number.isSafeInteger(owner.pid) || owner.pid <= 0) return;
			try { process.kill(owner.pid, 0); return; } catch (error) { if (errorCode(error) !== "ESRCH") return; }
			fs.unlinkSync(path.join(lockPath, "owner.json"));
			fs.rmdirSync(lockPath);
		} catch { /* a live process or a concurrent lock acquisition owns it */ }
		finally {
			try { fs.closeSync(recovery); } finally { fs.unlinkSync(recoveryPath); }
		}
	}
	async function transaction<T>(mutate: (state: OpenAIAuthState) => T | Promise<T>, operation?: { signal?: AbortSignal }): Promise<T> {
		requireKey();
		operation?.signal?.throwIfAborted();
		fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
		const lockId = randomUUID();
		const started = Date.now();
		for (;;) {
			operation?.signal?.throwIfAborted();
			try {
				fs.mkdirSync(lockPath, { mode: 0o700 });
				fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: process.pid, id: lockId }), { mode: 0o600 });
				break;
			} catch (error) {
				if (errorCode(error) !== "EEXIST") throw new OpenAICredentialStorageError("ChatGPT credential storage could not be locked.");
				removeAbandonedLock();
				if (Date.now() - started > 30_000) throw new OpenAICredentialStorageError(fs.existsSync(recoveryPath)
					? "ChatGPT credential recovery is blocked. Close LearnHarness and follow the offline recovery steps in docs/openai-chatgpt-auth.md. The encrypted vault has been preserved."
					: "ChatGPT credential storage is busy. Try again.");
				await delay(25, undefined, { signal: operation?.signal });
			}
		}
		try {
			cache = undefined;
			const state = readState();
			const result = await mutate(state);
			// A token may already have rotated: callers cancel waiting, never discard a completed mutation.
			writeState(state);
			return result;
		} finally {
			try {
				const owner = JSON.parse(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8"));
				if (owner.id === lockId) { fs.unlinkSync(path.join(lockPath, "owner.json")); fs.rmdirSync(lockPath); }
			} catch { /* original result takes precedence; stale owner is recovered on the next access */ }
		}
	}
	return { readState, transaction, ensure: () => transaction((state) => structuredClone(state)) };
}
