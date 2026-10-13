# Homebrew formula for Snitchy.
#
# Install (see README for details):
#   brew tap djmarcuslaw/snitchy https://github.com/djmarcuslaw/Snitchy
#   brew trust djmarcuslaw/snitchy
#   brew install --HEAD snitchy
#   sudo brew services start snitchy
class Snitchy < Formula
  desc "Real-time, per-app network connection log with a local web dashboard"
  homepage "https://github.com/djmarcuslaw/Snitchy"
  license "MIT"
  head "https://github.com/djmarcuslaw/Snitchy.git", branch: "main"

  depends_on :macos
  depends_on "python@3.13"

  def install
    # Snitchy is pure Python (standard library only), so "installing" is just
    # copying the package and writing a small launcher script.
    libexec.install "snitchy"
    python = Formula["python@3.13"].opt_bin/"python3.13"
    (bin/"snitchy").write <<~SH
      #!/bin/bash
      export PYTHONPATH="#{libexec}"
      exec "#{python}" -m snitchy "$@"
    SH
  end

  # `sudo brew services start snitchy` runs this at boot, as root (needed for
  # packet capture). Snitchy switches to an unprivileged user right after
  # tcpdump starts.
  service do
    run [opt_bin/"snitchy", "run"]
    require_root true
    keep_alive true
    log_path var/"log/snitchy.log"
    error_log_path var/"log/snitchy.log"
  end

  def caveats
    <<~EOS
      Start Snitchy now and at every boot (asks for your password):
        sudo brew services start snitchy

      Then open the dashboard:
        open http://localhost:8899

      Stop it:
        sudo brew services stop snitchy
    EOS
  end

  test do
    assert_match "snitchy", shell_output("#{bin}/snitchy --version")
  end
end
