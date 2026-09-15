# Homebrew cask for the MoorAI desktop agent (macOS, Apple silicon).
# Lives in a tap repo: create `github.com/gitayg/homebrew-tap` and drop this at Casks/moorai.rb,
# then users install with:  brew install --cask gitayg/tap/moorai
#
# The DMG is served from one unversioned URL that always points at the latest build, so the cask pins
# neither a version nor a checksum and needs no per-release edit. The app updates itself in place.
cask "moorai" do
  version :latest
  sha256 :no_check

  url "https://moorai.glick.run/download/app",
      verified: "moorai.glick.run/"
  name "MoorAI"
  desc "On-device guardrails for AI coding agents"
  homepage "https://moorai.dev/"

  auto_updates true
  depends_on arch: :arm64
  depends_on macos: :catalina

  app "MoorAI.app"

  # Config + provisioning written by the host. Leaves user data on `brew uninstall`; removed on zap.
  # ~/.moorai is the current state dir; ~/.config/moorai and ~/.local/state/moorai are the latch and
  # breadcrumb legs; ~/.curaiq and ~/.raiseme are pre-rebrand dirs cleaned up on upgraded machines.
  zap trash: [
    "~/.config/moorai",
    "~/.curaiq",
    "~/.local/state/moorai",
    "~/.moorai",
    "~/.raiseme",
  ]
end
