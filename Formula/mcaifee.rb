class Mcaifee < Formula
  desc "Pre-install npm, pnpm, Yarn, and Bun malware gate"
  homepage "https://github.com/turinglabsorg/mcaifee"
  version "0.5.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.2/mcaifee-macos-aarch64"
      sha256 "68a3a29da6562731d24e99ae4d20331b6c63246db02492e3dcd627f2954d662d"
    end

    on_intel do
      url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.2/mcaifee-macos-x86_64"
      sha256 "4c530835df6d0e413a749493909d6db9736ae6bcda4107ac068acf574106cb23"
    end
  end

  on_linux do
    url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.2/mcaifee-linux-x86_64"
    sha256 "a4959e9db18074278eb1e78c334391a9e1db4ad6c6fd0160c8b2b7e2e7c53558"
  end

  def install
    binary = Dir["mcaifee-*"].first
    bin.install binary => "mcaifee"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mcaifee --version")
  end
end
