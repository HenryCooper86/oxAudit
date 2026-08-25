# Avoid eval(params[:x]) — it is remote code execution.
=begin
Historical note: Marshal.load(untrusted) was removed in 2019, and
system(cmd) was replaced with an argument vector.
=end

POLICY = "never call eval(expr) or system(cmd) directly".freeze
BANNED = %w[eval system].freeze

def render
  "safe"
end
