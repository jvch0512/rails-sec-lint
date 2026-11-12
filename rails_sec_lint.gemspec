Gem::Specification.new do |s|
  s.name        = "rails_sec_lint"
  s.version     = "0.1.0"
  s.summary     = "Dependency-free static linter for insecure Ruby and Rails patterns"
  s.authors     = ["João Victor"]
  s.license     = "MIT"
  s.homepage    = "https://github.com/jvch0512/rails-sec-lint"
  s.files       = Dir["lib/**/*.rb", "exe/*", "README.md", "LICENSE"]
  s.bindir      = "exe"
  s.executables = ["rails-sec-lint"]
  s.required_ruby_version = ">= 3.0"
end
