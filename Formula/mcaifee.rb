class Mcaifee < Formula
  desc "Pre-install npm, pnpm, Yarn, and Bun malware gate"
  homepage "https://github.com/turinglabsorg/mcaifee"
  version "0.5.4"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.4/mcaifee-macos-aarch64"
      sha256 "7cabc30b180bd0ebb8deb53ae74168da4df6c61be27ac7a01b8aca869134ed46"
    end

    on_intel do
      url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.4/mcaifee-macos-x86_64"
      sha256 "b92cd6fa9cee5209e9af9ce52a7cf5af1f54913ce854ff88cab83f225c8f8839"
    end
  end

  on_linux do
    url "https://github.com/turinglabsorg/mcaifee/releases/download/v0.5.4/mcaifee-linux-x86_64"
    sha256 "2e7122bfeb7babfd212be26991960942e926702c6e1108312a357fcc1ff0f8a9"
  end

  def install
    binary = Dir["mcaifee-*"].first
    bin.install binary => "mcaifee"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mcaifee --version")
  end
end
