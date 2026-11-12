# rails-sec-lint

Dependency-free **static security linter for Ruby and Rails**. Flags 16 classes of insecure patterns (SQL injection, command injection, unsafe reflection, XSS, unsafe deserialization, mass assignment, CSRF off, open redirect, path traversal, SSRF, weak crypto, bad randomness, disabled TLS verification, hard-coded secrets) with CWE references. Pure Ruby standard library, runs on Ruby 3.0+.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
ruby -Ilib exe/rails-sec-lint app/                 # text report
ruby -Ilib exe/rails-sec-lint --format json .      # machine readable
ruby -Ilib exe/rails-sec-lint --fail-on high app/  # exit 2 at high or critical
```

Example on `samples/users_controller.rb`:

```
[HIGH    ] RSL001 samples/users_controller.rb:5  (CWE-89)
    @user = User.where("name = '#{params[:name]}'").first
    String interpolation in an ActiveRecord query (SQL injection). Use placeholders...
```

## Rules

| ID | Severity | Issue | CWE |
|----|----------|-------|-----|
| RSL001 | high | SQL built by interpolation | 89 |
| RSL002 | critical | shell command with interpolation | 78 |
| RSL003 | critical | `eval` family | 95 |
| RSL004 | high | unsafe reflection (`send`, `constantize` on input) | 470 |
| RSL005 | high | `html_safe` / `raw` on request data | 79 |
| RSL006 | high | `Marshal.load`, unsafe `YAML.load` | 502 |
| RSL007 | high | `permit!` | 915 |
| RSL008 | medium | CSRF protection disabled | 352 |
| RSL009 | medium | open redirect | 601 |
| RSL010 | high | path traversal | 22 |
| RSL011 | high | SSRF | 918 |
| RSL012 | medium | MD5 / SHA1 | 327 |
| RSL013 | medium | `rand` for security values | 330 |
| RSL014 | high | TLS verification off | 295 |
| RSL015 | high | hard-coded credential | 798 |
| RSL016 | medium | `render inline:` with interpolation | 79 |

Suppress with `# sec-lint:disable` (all rules) or `# sec-lint:disable RSL012,RSL013` on the same line.

## Limits

This is a line-based pattern linter, so it has no data-flow analysis: it will produce false positives and miss multi-line constructs. For production use pair it with [Brakeman](https://brakemanscanner.org/), which does real Rails-aware analysis. The point here is a small, readable rule set that is easy to extend.

## Development

```bash
rake test
```

MIT licensed.
