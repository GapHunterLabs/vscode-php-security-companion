# PHP Security Companion (VS Code)

5 turnkey PHP injection-sink checks, live in the editor as you type —
no configuration, no data leaves your editor.

**v0.1, pilot.** Part of the Gap Hunter Labs VS Code workstream. This
combines 5 separate IntelliJ-family plugins
(`php-sql-injection-companion`, `php-function-injection-companion`,
`php-open-redirect-companion`, `php-file-inclusion-companion`,
`php-shell-injection-companion`) into one extension — a single
"PHP Security Companion" with 5 rules is a better fit for VS Code's
ecosystem than 5 near-identical tiny extensions (same reasoning
ESLint bundles many rules into one extension, not one per rule).

**Confirmed real gap, not assumed:** "PHP Inspections (EA Extended)"
(one of the most widely used PHP inspection tools) does not cover any
of these 5 checks in its documented security feature list — confirmed
by reading it before building each of the 5 original IntelliJ-family
plugins. A search of VS Code Marketplace for a turnkey, out-of-the-box
PHP taint/injection scanner covering these specific sinks came up
empty too (general SAST frameworks like Semgrep exist but require
configuring rule sets — not a zero-config linter like this).

## What it checks

| Rule | Flags |
|---|---|
| `sql-injection` | `mysqli_query(`/`->query(`/`->exec(` built with string interpolation/concatenation instead of a prepared-statement placeholder |
| `function-injection` | `call_user_func(`/`call_user_func_array(` with a callable name taken directly from `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` |
| `open-redirect` | `header(...)` setting a `Location:` value taken directly from a superglobal |
| `file-inclusion` | `include`/`include_once`/`require`/`require_once` with a path taken directly from a superglobal (LFI/RFI) |
| `shell-injection` | `eval`/`exec`/`shell_exec`/`system`/`passthru`/`popen` built with string interpolation/concatenation |

Diagnostics show up in the editor (squiggly underline) and the
Problems panel, live as you edit any `.php` file — no command to run.

**v0.1 scope, honestly noted (same as the IntelliJ-family originals):**
plain-text/regex matching, not real PHP parsing — a value that flows
through an intermediate variable before reaching the sink isn't
traced (real taint/data-flow analysis is a much bigger undertaking,
out of scope here). A call built entirely from static literals is
correctly never flagged.

## Privacy

See [PRIVACY.md](PRIVACY.md) — zero network calls, everything runs
against files already open in your editor.

## Development

```bash
npm install
npm run compile   # or: npm run watch
npm test
```

Press F5 (with this folder open) to launch an Extension Development
Host against a real `.php` file. To build an installable package
without publishing:

```bash
npx @vscode/vsce package
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
