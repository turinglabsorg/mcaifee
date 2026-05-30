class Mcaifee < Formula
  desc "Pre-install npm, pnpm, Yarn, and Bun malware gate"
  homepage "https://github.com/turinglabsorg/mcaifee"
  version "0.5.3"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.3/mcaifee-macos-aarch64"
      sha256 "60da5b6c3e8cf8dea1e5384450106d0fa1fc2c5b1431a688b534e24c23f8ef57"
    end

    on_intel do
      url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.3/mcaifee-macos-x86_64"
      sha256 "78ff10e588b43b867697163d4d92c21f138ea4a872eafb83cfbbd6ac4e7f6d26"
    end
  end

  on_linux do
    url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.3/mcaifee-linux-x86_64"
    sha256 "15537f5e922fdb38b205ee11db4f5fdd5dfd0f005c992c025649628e0a7d9d51"
  end

  def install
    binary = Dir["mcaifee-*"].first
    bin.install binary => "mcaifee"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mcaifee --version")
  end
end
