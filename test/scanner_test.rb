# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "rails_sec_lint"

class ScannerTest < Minitest::Test
  def ids(code)
    RailsSecLint.scan_source(code).map { |f| f.rule.id }
  end

  def test_sql_injection_by_interpolation_but_not_placeholders
    assert_includes ids(%q{User.where("name = '#{params[:n]}'")}), "RSL001"
    assert_includes ids(%q{User.order("#{params[:sort]} asc")}), "RSL001"
    assert_empty ids(%q{User.where("name = ?", params[:n])})
    assert_empty ids(%q{User.where(name: params[:n])})
  end

  def test_command_injection
    assert_includes ids(%q{system("ls #{params[:d]}")}), "RSL002"
    assert_includes ids("out = `cat \#{file}`"), "RSL002"
    assert_empty ids(%q{system("ls", params[:d])})
  end

  def test_eval_and_unsafe_reflection
    assert_includes ids("eval(params[:code])"), "RSL003"
    assert_includes ids("params[:klass].constantize.new"), "RSL004"
    assert_includes ids("obj.public_send(params[:m])"), "RSL004"
  end

  def test_xss_and_template_injection
    assert_includes ids("params[:bio].html_safe"), "RSL005"
    assert_includes ids("raw(params[:x])"), "RSL005"
    assert_includes ids(%q{render inline: "<%= #{params[:t]} %>"}), "RSL016"
  end

  def test_deserialization
    assert_includes ids("Marshal.load(cookies[:s])"), "RSL006"
    assert_includes ids("YAML.load(File.read(f))"), "RSL006"
    assert_empty ids("YAML.safe_load(text)")
  end

  def test_mass_assignment_csrf_redirect_path
    assert_includes ids("params.require(:user).permit!"), "RSL007"
    assert_includes ids("skip_before_action :verify_authenticity_token"), "RSL008"
    assert_includes ids("redirect_to params[:next]"), "RSL009"
    assert_includes ids("send_file params[:path]"), "RSL010"
    assert_empty ids("redirect_to root_path")
  end

  def test_ssrf_weak_crypto_randomness_tls_secrets
    assert_includes ids("URI.open(params[:url])"), "RSL011"
    assert_includes ids("Digest::MD5.hexdigest(x)"), "RSL012"
    assert_includes ids("token = rand(1000)"), "RSL013"
    assert_empty ids("token = SecureRandom.hex(16)")
    assert_includes ids("http.verify_mode = OpenSSL::SSL::VERIFY_NONE"), "RSL014"
    secret = "A" * 8 + "b" * 8 + "9" * 8   # assembled at runtime, no credential-like literal in the repo
    assert_includes ids(%(api_key = "#{secret}")), "RSL015"
    assert_empty ids('api_key = ENV["API_KEY"]')
  end

  def test_comments_and_disable_markers
    assert_empty ids("# eval(params[:x])")
    assert_empty ids("=begin\neval(params[:x])\n=end")
    assert_empty ids("eval(params[:x]) # sec-lint:disable")
    assert_empty ids("Digest::MD5.new # sec-lint:disable RSL012")
    assert_includes ids("Digest::MD5.new # sec-lint:disable RSL001"), "RSL012"
  end

  def test_line_numbers_and_scan_path
    Dir.mktmpdir do |d|
      File.write(File.join(d, "a.rb"), "x = 1\nSystem = 2\nredirect_to params[:u]\n")
      Dir.mkdir(File.join(d, "vendor"))
      File.write(File.join(d, "vendor", "b.rb"), "eval(params[:x])\n")
      f = RailsSecLint.scan_path(d)
      assert_equal 1, f.size
      assert_equal 3, f.first.line
    end
  end

  def test_cli_exit_codes_and_json
    exe = File.expand_path("../exe/rails-sec-lint", __dir__)
    sample = File.expand_path("../samples", __dir__)
    out = IO.popen([RbConfig.ruby, exe, "--format", "json", sample], &:read)
    data = JSON.parse(out)
    assert_operator data.size, :>=, 6
    assert_includes data.map { |h| h["id"] }, "RSL002"
    Process.wait(spawn(RbConfig.ruby, exe, sample, out: File::NULL)); assert_equal 2, $?.exitstatus
    Dir.mktmpdir do |clean|
      File.write(File.join(clean, "ok.rb"), "User.where(name: params[:n])\n")
      Process.wait(spawn(RbConfig.ruby, exe, clean, out: File::NULL)); assert_equal 0, $?.exitstatus
    end
    Dir.mktmpdir do |medium|
      File.write(File.join(medium, "m.rb"), "redirect_to params[:next]\n")
      Process.wait(spawn(RbConfig.ruby, exe, "--fail-on", "high", medium, out: File::NULL)); assert_equal 0, $?.exitstatus
      Process.wait(spawn(RbConfig.ruby, exe, "--fail-on", "medium", medium, out: File::NULL)); assert_equal 2, $?.exitstatus
    end
  end
end
