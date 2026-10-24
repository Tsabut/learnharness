# OpenAI: API key or ChatGPT plan

Settings → Keys → OpenAI offers an explicit API key / Sign in with ChatGPT choice. OAuth never silently falls back to a saved or environment API key. Search and dictation retain their separate service keys.

Use **Continue with ChatGPT** in the desktop app. It opens the system browser; complete consent there and return to LearnHarness. Account registrations are saved separately, so reconnecting an existing account reuses its issued client ID. The account picker can add or switch registrations. Sign out attempts remote refresh-token revocation, clears local tokens and preserves the registration for a later sign-in. A failed remote revocation is reported explicitly.

The selected account's public `/v1/models` list is intersected with models supported by the bundled engine; an API-key catalog is never substituted. Completed inference, rather than the picker, confirms model access. All SIWC requests use the public Responses API with `store: false` and `stream: true`; incomplete or interrupted streams fail explicitly.

The existing money meters show **API estimates**, not ChatGPT subscription charges. OAuth model rows show **ChatGPT plan**. Actual app usage and permissions are managed at https://chatgpt.com/settings/usage.

## Plan usage and recovery

The first successful plan-enabled connection shows **You're using your ChatGPT plan**. Dismissing it records an acknowledgement in that registration's encrypted vault record, rather than browser storage. It does not repeat when the same registration reconnects and does not interrupt an in-progress lesson.

The model control shows **Using ChatGPT plan** and **Manage usage** when its effective model uses the `openai` provider with connected OAuth. Other providers and explicit API-key mode do not show that indicator. Settings also link to ChatGPT usage. Sign-in actions use the approved **Continue with ChatGPT** label and ChatGPT logo assets.

Exact structured `subscription_sharing_usage_limit_exceeded` and `subscription_sharing_usage_unavailable` errors are recognized both before streaming and in `response.failed`. The connection is preserved, new plan inference pauses, and the recovery UI makes **Manage usage** the primary action. **Try again** deliberately allows another attempt; neither the SDK nor this UI loops through billable retries or switches to an API key. Plain diagnostic text and unrelated HTTP 429s are not treated as a subscription limit. Usage status is refreshed on turn/job events and window focus, with polling only while browser sign-in is pending.

## Credential security

Electron protects a random vault key with OS `safeStorage` (Windows DPAPI). Only its private Next child receives the unwrapped key. The server keeps an AES-256-GCM credential vault under `data/openai-auth/vault.enc`; registration, account identity and rotating tokens are written atomically under a cross-process lock. Tokens and authorization URLs never enter renderer status or browser storage. Browser-helper environments exclude the vault key.

Stale-lock reclamation has its own exclusive guard so two recovering processes cannot remove a newly acquired live lock. If a process crashes inside that short synchronous recovery section, the `data/openai-auth/vault.recovery` guard is deliberately not broken automatically. Close **all** LearnHarness and helper/server processes before removing only that guard file; leave `vault.enc` and `openai-vault-key.enc` intact, then reopen the app. A remaining `vault.lock` with a dead owner is reclaimed normally. Do not remove lock files while a process might be rotating credentials. This rare availability limitation preserves refresh-token safety rather than guessing that a live lock is stale.

API-key storage remains the existing, separate `auth.json` contract. If the protected vault cannot be opened, OAuth fails closed. An explicit API-key mode selection can recover API-key use for the current session without modifying the inaccessible vault.

## CI and platform storage checks

The existing CI standalone matrix runs the OAuth protocol, encrypted-vault, request-isolation and desktop-security tests on Windows x64, macOS arm64 and Linux x64 before building that OS's standalone payload. These deterministic tests do not contact a real ChatGPT account. CI has read-only repository permissions and does not publish installers or releases; the separate manual desktop-release workflow retains its artifact-only rehearsal policy.

`node node_modules/electron/cli.js scripts/smoke-oauth-storage.cjs --expect-encrypted` uses actual Electron `safeStorage` in two independent processes with an isolated scratch profile. Windows checks DPAPI and macOS checks Keychain persistence. The smoke verifies the same 256-bit key is recovered after restart and the saved bytes contain neither the key's raw nor base64 representation. It prints no key, digest, credential or authorization URL. Scratch profiles are removed afterward.

Linux additionally requires a supported OS secret store. `basic_text` and an unknown backend disable OAuth; API-key mode remains available. CI intentionally checks this refusal using real Electron with `--linux-basic --expect-unavailable` under Xvfb, without installing a keyring or changing host settings. Its JSON result is `storage: "unavailable"` with `unavailableFailClosed: true`, which confirms safe refusal rather than encrypted credential persistence. The no-window Linux storage probe alone uses `--no-sandbox` for Ubuntu CI runners that restrict npm Electron's user namespaces; production Electron configuration is unchanged.

On a Linux desktop with an unlocked supported keyring, run the storage smoke with `--expect-encrypted` to require a real encrypted round trip. A successful basic-text refusal is not evidence of Linux keyring integration. Likewise, the unsigned macOS CI runtime does not establish Keychain access behavior across signed application updates; verify the signed release separately. These boundaries follow Electron 44's [safeStorage contract](https://github.com/electron/electron/blob/v44.4.1/docs/api/safe-storage.md).

## Safe local Windows verification

Build using `docs/desktop-release.md` and `npx electron-builder --win --x64 --publish never`. Do not run the installer over an existing installation during development. Launch `dist/win-unpacked/LearnHarness.exe` with an absolute `LH_USER_DATA_DIR` pointing to a new empty test directory. The shell respects optional absolute `LH_DATA_DIR` and `LH_AUTH_FILE` overrides. Never point tests at the installed app's records.

Check sign-in without `OPENAI_API_KEY`, an actual tool-using lesson, restart persistence, token renewal and sign-out. Deterministic mocked protocol tests are not a substitute for this account-dependent check.

## Scope and remaining release checks

- The protected browser bridge and key bootstrap currently run in the packaged Electron desktop application. A plain `npm run dev` or standalone web/server process does not gain ChatGPT OAuth automatically. API-key mode is unchanged there.
- Each user authorizes their own ChatGPT account/workspace and plan use. No shared account, partner API key, client secret or preconfigured credentials ship in the app. Account eligibility, model availability, region/workspace policy and limits remain controlled by OpenAI.
- Real account testing on Windows x64 completed browser consent, account model discovery without an API key, a streamed tool-using lesson, continuation after restart, refresh-token rotation and revocation on sign-out. For renewal, the isolated profile's cached expiry was forced into the past; natural expiry was not awaited.
- CI exercises protocol/security mocks, native renderers, OS storage and standalone startup on the listed platforms. It does not complete a real ChatGPT browser consent or inference on macOS/Linux, exercise every listed model, or verify multiple real accounts.
- Linux encrypted persistence still needs a manual run with an unlocked supported desktop keyring; CI tests the real insecure-backend refusal. Signed/notarized macOS release Keychain access and upgrade continuity require a signed release check.
- OpenAI's SIWC route is in preview and has [capability limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations). This change does not add hosted tool support, transcription, or an alternative payment method for search/dictation.
- Plan requests normalize older adapter payloads too: system input messages become developer messages, flat local function/custom definitions become `additional_tools`, and documented unsupported HTTP parameters are omitted after caller transforms. Tool names and call IDs are preserved. Hosted tools and `tool_search` history fail locally rather than being silently removed.

The package version and auto-update policy remain upstream's. CI verification does not publish a release or install over user data. Release signing, tagging and publication remain maintainer-controlled.

## Protocol sources

- https://developers.openai.com/siwc/token-sharing-open-source/sign-in
- https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions
- https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery
- https://developers.openai.com/siwc/ui-ux-guidelines
- https://developers.openai.com/siwc/website
