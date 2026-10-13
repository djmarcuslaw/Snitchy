# Homebrew formula for Snitchy.
#
# Install (see README for details):
#   brew tap djmarcuslaw/snitchy https://github.com/djmarcuslaw/Snitchy
#   brew trust djmarcuslaw/snitchy
#   brew install --HEAD snitchy
#   sudo snitchy install-service
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
    # -I (isolated mode) ignores PYTHONPATH and, importantly, the current
    # folder: otherwise `sudo snitchy` run from a folder containing its own
    # "snitchy" directory would import that code instead, as root.
    (bin/"snitchy").write <<~SH
      #!/bin/bash
      exec "#{python}" -I -c 'import sys; sys.path.insert(0, "#{libexec}"); from snitchy.cli import main; main()' "$@"
    SH
  end

  # No `service do` block on purpose: a root service running from Homebrew's
  # folders (owned by your user account) would let anything running as you
  # get root. `sudo snitchy install-service` installs a root-owned copy that
  # runs with Apple's own Python instead. See snitchy/service.py.

  def caveats
    <<~EOS
      Install (or, after `brew upgrade`, update) the background service.
      It asks for your password:
        sudo snitchy install-service

      Then open the dashboard (this also signs you in):
        snitchy open

      Remove it:
        sudo snitchy uninstall-service
    EOS
  end

  test do
    assert_match "snitchy", shell_output("#{bin}/snitchy --version")
  end
end
