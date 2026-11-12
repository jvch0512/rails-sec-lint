# frozen_string_literal: true

module RailsSecLint
  Rule = Struct.new(:id, :severity, :pattern, :message, :cwe, keyword_init: true)

  USER_INPUT = /params\[|params\.(?:fetch|dig|require)|request\.(?:params|parameters|query_parameters|body)|cookies\[/

  RULES = [
    Rule.new(id: "RSL001", severity: :high, cwe: "CWE-89",
             pattern: /\.(?:where|order|group|having|joins|select|pluck|find_by_sql|exists\?)\(\s*(?:"[^"]*#\{|'[^']*#\{|["'][^"']*["']\s*\+|%[qQ]?\{[^}]*#\{)/,
             message: "String interpolation in an ActiveRecord query (SQL injection). Use placeholders: where('a = ?', x) or hashes"),
    Rule.new(id: "RSL002", severity: :critical, cwe: "CWE-78",
             pattern: /(?:\bsystem|\bexec|\bspawn|\bpopen|Open3\.\w+)\s*\(?\s*["'][^"']*#\{|`[^`]*#\{/,
             message: "Shell command built with interpolation (command injection). Pass arguments as an array: system('cmd', arg)"),
    Rule.new(id: "RSL003", severity: :critical, cwe: "CWE-95",
             pattern: /\b(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*(?!["'][^#]*["']\s*\)?\s*$)/,
             message: "eval-style code execution; never evaluate data derived from users"),
    Rule.new(id: "RSL004", severity: :high, cwe: "CWE-470",
             pattern: /\.(?:send|public_send|constantize|safe_constantize)\b.*(?:#{USER_INPUT.source})|(?:#{USER_INPUT.source}).*\.(?:constantize|safe_constantize)\b/,
             message: "Reflection driven by request data (unsafe reflection / arbitrary method call)"),
    Rule.new(id: "RSL005", severity: :high, cwe: "CWE-79",
             pattern: /(?:#{USER_INPUT.source}).*\.html_safe\b|\braw\s*\(?\s*(?:#{USER_INPUT.source})|\bhtml_safe\b.*(?:#{USER_INPUT.source})/,
             message: "Request data marked html_safe or passed to raw (XSS)"),
    Rule.new(id: "RSL006", severity: :high, cwe: "CWE-502",
             pattern: /\bMarshal\.(?:load|restore)\b|\bYAML\.load\s*\((?!.*safe)|\bYaml\.load\b|\bYAML\.unsafe_load\b/,
             message: "Unsafe deserialization (Marshal / YAML.load). Use YAML.safe_load with permitted classes or JSON"),
    Rule.new(id: "RSL007", severity: :high, cwe: "CWE-915",
             pattern: /params(?:\.require\([^)]*\))?\.permit!/,
             message: "permit! allows mass assignment of every attribute"),
    Rule.new(id: "RSL008", severity: :medium, cwe: "CWE-352",
             pattern: /skip_(?:before|forgery)_(?:action|protection)[^#\n]*(?::verify_authenticity_token|protect_from_forgery)|skip_forgery_protection|protect_from_forgery\s+with:\s*:null_session/,
             message: "CSRF protection disabled or weakened"),
    Rule.new(id: "RSL009", severity: :medium, cwe: "CWE-601",
             pattern: /redirect_to\s*\(?\s*(?:#{USER_INPUT.source})/,
             message: "Open redirect: redirect_to with request data. Use an allowlist or only_path: true"),
    Rule.new(id: "RSL010", severity: :high, cwe: "CWE-22",
             pattern: /(?:send_file|send_data|File\.(?:read|open|write|delete)|IO\.read|render\s+(?:file|template):?)\s*\(?\s*(?:#{USER_INPUT.source})/,
             message: "File path built from request data (path traversal)"),
    Rule.new(id: "RSL011", severity: :high, cwe: "CWE-918",
             pattern: /(?:URI\.open|Net::HTTP\.(?:get|get_response|post|start)|HTTParty\.\w+|Faraday\.\w+|open-uri|\bopen)\s*\(?\s*(?:#{USER_INPUT.source})/,
             message: "Outbound request to a URL taken from request data (SSRF)"),
    Rule.new(id: "RSL012", severity: :medium, cwe: "CWE-327",
             pattern: /Digest::(?:MD5|SHA1)\b|OpenSSL::Digest(?:::|\.new\()['"]?(?:MD5|SHA1)/i,
             message: "Weak hash algorithm; use SHA-256+ (and bcrypt/argon2 for passwords)"),
    Rule.new(id: "RSL013", severity: :medium, cwe: "CWE-330",
             pattern: /(?:token|secret|password|nonce|key|otp|session)\w*\s*=.*\b(?:rand|Random\.rand|Kernel\.rand|srand)\b/i,
             message: "Non-cryptographic randomness for a security value; use SecureRandom"),
    Rule.new(id: "RSL014", severity: :high, cwe: "CWE-295",
             pattern: /VERIFY_NONE|verify_ssl:\s*false|ssl_verify:\s*false|verify:\s*false/,
             message: "TLS certificate verification disabled"),
    Rule.new(id: "RSL015", severity: :high, cwe: "CWE-798",
             pattern: /(?:secret|password|passwd|api_?key|token|private_key)\w*\s*[:=]\s*["'][A-Za-z0-9+\/=_\-]{16,}["']/i,
             message: "Hard-coded credential; read it from the environment or encrypted credentials"),
    Rule.new(id: "RSL016", severity: :medium, cwe: "CWE-79",
             pattern: /render\s+(?:inline|html):\s*.*(?:#\{|#{USER_INPUT.source})/,
             message: "render inline/html with interpolated data (template injection / XSS)")
  ].freeze
end
