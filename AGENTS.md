# zigwhats

## Scope

Zig codebase for a WhatsApp Web client library.

## Development Priorities

Order of importance:
1. protocol correctness
2. behavioral stability
3. debuggability
4. performance and memory
5. local elegance

Do not trade correctness for small optimizations.

## Style

- Prefer small functions with explicit data flow.
- Keep ownership and lifetime rules obvious.
- Prefer existing local patterns over new abstractions.
- Add comments only where behavior is non-obvious.
- Keep logs high-signal. Avoid noisy narration logs.
- Do not leave experimental code paths enabled by default.

## Refactoring Rules

- Refactor in narrow slices.
- Keep changes easy to validate with logs and tests.
- When changing protocol-sensitive code, avoid mixing unrelated cleanup into the same patch.
- If a fast path exists for a protocol stanza, it must be justified by measurement and validated against the canonical encoder.

## Performance Rules

- Prefer reusable buffers over repeated heap allocation on hot paths.
- Prefer borrowed data when ownership is clearly bounded and safe.
- Do not add retained-capacity or pre-sizing heuristics without measuring the impact.
- For protocol-sensitive paths, correctness beats micro-optimization.
- Avoid custom encoders for critical control stanzas unless byte-for-byte validated.

## Validation

Always validate with both:

```bash
zig build test
zig build e2e
```

For runtime-sensitive changes also validate with:

```bash
zig build run -Doptimize=ReleaseSmall -Dlog_level=debug
```

When behavior differs between test/e2e and real runtime, trust the real runtime first.

## Current Engineering Notes

- Live delivery depends on a correctly encoded `active` IQ.
- Incoming message decryption is still an active problem area.
- `ClientOptions.experimental_post_login_init` is for gated experiments only and should stay off unless specifically validating it.

## When Working On Bugs

- Reproduce first.
- Identify the exact stage that fails.
- Fix the smallest thing that explains the observed behavior.
- Re-run the same reproduction after the fix.
- If a fix only works for tests but not real runtime, it is not done.
