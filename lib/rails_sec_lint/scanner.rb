# frozen_string_literal: true

require "json"
require_relative "rules"

module RailsSecLint
  Finding = Struct.new(:rule, :file, :line, :text, keyword_init: true) do
    def to_h
      { id: rule.id, severity: rule.severity, cwe: rule.cwe, message: rule.message, file: file, line: line, code: text.strip }
    end
  end

  SEVERITIES = %i[low medium high critical].freeze
  DISABLE = /sec-lint:disable(?:\s+(RSL\d{3}(?:\s*,\s*RSL\d{3})*))?/
  MAX_BYTES = 1_000_000

  module_function

  def scan_source(source, file = "(string)", rules: RULES)
    out = []
    in_block_comment = false
    source.each_line.with_index(1) do |line, no|
      if line.start_with?("=begin") then in_block_comment = true
      elsif line.start_with?("=end") then in_block_comment = false
      end
      next if in_block_comment
      stripped = line.lstrip
      next if stripped.start_with?("#") || stripped.empty?
      disabled = line[DISABLE, 0] && (line[DISABLE, 1]&.split(/\s*,\s*/) || :all)
      rules.each do |rule|
        next unless line.match?(rule.pattern)
        next if disabled == :all || (disabled.is_a?(Array) && disabled.include?(rule.id))
        out << Finding.new(rule: rule, file: file, line: no, text: line.chomp)
      end
    end
    out
  end

  def scan_path(path)
    files = File.file?(path) ? [path] : Dir.glob(File.join(path, "**", "*.{rb,erb,rake,ru}")).sort
    files.reject! { |f| f.include?("/vendor/") || f.include?("/node_modules/") || f.include?("/.git/") }
    files.flat_map do |f|
      next [] if File.size(f) > MAX_BYTES
      scan_source(File.read(f, encoding: "UTF-8", invalid: :replace, undef: :replace), f)
    end
  end

  def worst(findings)
    findings.map { |f| SEVERITIES.index(f.rule.severity) }.max
  end
end
