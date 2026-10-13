# Idempotency Replay Tester

A Burp Suite extension for testing whether an API enforces idempotency correctly when the same request is retried, when a key is missing, or when the same key is reused with a different payload.

This tool is designed for security and API testing workflows where you need to confirm whether a backend correctly prevents duplicate business effects (for example duplicate orders, charges, or account changes) under repeated or replayed requests.

## What it does

The extension adds a Burp tab named `Idempotency Tester` and provides context-menu actions for loading HTTP requests from Proxy or Repeater. It can run several replay scenarios:

- Same idempotency key sent in parallel to the same endpoint
- Missing idempotency key sent in parallel to the same endpoint
- Same idempotency key reused with a changed payload

For each scenario, it sends requests, records response metadata, and compares response bodies and replay signals to help identify suspicious behavior.

## Included scenarios

1. Same key, parallel identical requests
   - Sends multiple identical requests with the same `Idempotency-Key` concurrently.
   - Helps determine whether the server responds with replay behavior or duplicated effects.

2. Missing key, parallel identical requests
   - Sends multiple identical requests without an idempotency key.
   - Helps demonstrate whether the backend treats repeated requests as independent transactions.

3. Reuse key with changed request
   - Sends a second request to the same endpoint with a different body/query while reusing the same key.
   - Helps reveal whether the server improperly accepts a different payload under the same idempotency key.

## Features

- Burp tab-based UI
- Context menu integration for loading requests directly from Burp
- Scenario selection and configurable parallel sends
- Confirmation guard to reduce accidental destructive testing
- Response comparison with SHA-256-style fingerprints
- Displays replay indicators such as `Idempotency-Replayed` and `Idempotency-Status`

## Requirements

- Burp Suite
- Jython support enabled in Burp
- A target API that accepts replay or idempotency-key behavior testing

## Installation

1. Open Burp Suite.
2. Go to `Extender` > `Extensions`.
3. Add a new extension using the Python/Jython loader.
4. Load `idempotency_replay_tester.py`.
5. The extension will appear as a new tab named `Idempotency Tester`.

## Usage

1. In Burp, right-click a request in Proxy or Repeater.
2. Choose one of the context-menu actions:
   - `Load as idempotency test request`
   - `Load as changed-payload reuse request`
3. Select the test scenario from the extension tab.
4. Enter or generate an `Idempotency-Key`.
5. Confirm the test and review the results.
6. Check whether the server reports replay behavior or whether multiple successful responses indicate duplicate effects.

## Important warning

This tool is intended for controlled testing in a safe environment. It can trigger duplicate business actions such as duplicate orders or payments if the target application does not enforce idempotency correctly. Use it only against systems you are authorized to test.

## File overview

- `idempotency_replay_tester.py` — Burp extension source code
- `README.md` — usage and overview documentation

## Notes

The extension uses Burp's legacy Jython API and is designed for a direct, practical workflow while testing idempotency and replay semantics against HTTP endpoints.
