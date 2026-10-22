// Widely installed VS Code-family extension ids (publisher.name, lower-case): the reference set for the
// IDE-extension typosquat and publisher-impersonation checks in cli/ide-extensions.mjs. An attacker
// cloning a listing copies one of these names. Curated by hand from the most-installed Marketplace and
// Open VSX listings and the AI coding extensions; ids only.

export const POPULAR_IDE_EXTENSIONS = [
  // languages and runtimes
  "ms-python.python", "ms-python.vscode-pylance", "ms-python.debugpy", "ms-python.black-formatter", "ms-python.isort",
  "ms-python.flake8", "charliermarsh.ruff", "ms-toolsai.jupyter", "ms-vscode.cpptools", "ms-vscode.cmake-tools",
  "ms-vscode.makefile-tools", "ms-vscode.powershell", "ms-dotnettools.csharp", "ms-dotnettools.csdevkit", "redhat.java",
  "vscjava.vscode-java-pack", "golang.go", "rust-lang.rust-analyzer", "dart-code.dart-code", "dart-code.flutter",
  "vue.volar", "svelte.svelte-vscode", "angular.ng-template", "denoland.vscode-deno", "xdebug.php-debug",
  "bmewburn.vscode-intelephense-client", "juanblanco.solidity", "nomicfoundation.hardhat-solidity", "prisma.prisma",
  "graphql.vscode-graphql", "hashicorp.terraform", "redhat.vscode-yaml", "redhat.vscode-xml", "tamasfe.even-better-toml",
  // editing, formatting, linting
  "esbenp.prettier-vscode", "dbaeumer.vscode-eslint", "stylelint.vscode-stylelint", "biomejs.biome",
  "editorconfig.editorconfig", "streetsidesoftware.code-spell-checker", "usernamehw.errorlens", "bradlc.vscode-tailwindcss",
  "christian-kohler.path-intellisense", "formulahendry.code-runner", "formulahendry.auto-rename-tag",
  "yzhang.markdown-all-in-one", "davidanson.vscode-markdownlint", "aaron-bond.better-comments", "gruntfuggly.todo-tree",
  "oderwat.indent-rainbow", "njpwerner.autodocstring", "dsznajder.es7-react-js-snippets", "ecmel.vscode-html-css",
  "wix.vscode-import-cost", "mikestead.dotenv",
  // git, remote, containers, cloud
  "eamodio.gitlens", "mhutchie.git-graph", "donjayamanne.githistory", "github.vscode-pull-request-github",
  "github.vscode-github-actions", "gitlab.gitlab-workflow", "atlassian.atlascode", "ms-vscode-remote.remote-ssh",
  "ms-vscode-remote.remote-containers", "ms-vscode-remote.remote-wsl", "ms-azuretools.vscode-docker",
  "ms-kubernetes-tools.vscode-kubernetes-tools", "ms-vsliveshare.vsliveshare", "ritwickdey.liveserver",
  "humao.rest-client", "rangav.vscode-thunder-client", "mtxr.sqltools", "ms-mssql.mssql",
  "alefragnani.project-manager", "alefragnani.bookmarks",
  // themes and icons
  "pkief.material-icon-theme", "vscode-icons-team.vscode-icons", "zhuangtongfa.material-theme",
  "dracula-theme.theme-dracula", "github.github-vscode-theme", "johnpapa.vscode-peacock",
  // AI coding extensions
  "github.copilot", "github.copilot-chat", "anthropic.claude-code", "saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline",
  "kilocode.kilo-code", "continue.continue", "codeium.codeium", "tabnine.tabnine-vscode", "sourcegraph.cody-ai",
  "supermaven.supermaven", "google.geminicodeassist", "openai.chatgpt", "amazonwebservices.amazon-q-vscode",
  "amazonwebservices.aws-toolkit-vscode", "visualstudioexptteam.vscodeintellicode"
];
