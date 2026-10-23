// Fixtures for the trust-boundary change check (#85): positives per signal and benign near-misses.
// Each edit fixture is { name, path, before, after, expect } (before null: a new file); each command
// fixture is { name, command, manifests, expect }, where manifests are files placed in cwd first.

const PKG = (deps, dev = {}) => JSON.stringify({ name: "svc", version: "1.0.0", scripts: { build: "tsc", test: "node --test" }, dependencies: deps, devDependencies: dev }, null, 2) + "\n";
const SERVER_JS = `import express from "express";
const app = express();
app.get("/health", (req, res) => res.send("ok"));
app.get("/users", listUsers);
app.listen(process.env.PORT || 3000);
`;
const CLIENT_PY = `import os
import requests

BASE = "https://api.billing.internal.acme.io/v2"

def charge(amount):
    token = os.environ.get("BILLING_API_TOKEN")
    return requests.post(BASE + "/charge", json={"amount": amount}, headers={"Authorization": token})
`;

export const POSITIVE_EDITS = [
  // ---- new-dependency ----
  { name: "package.json: a new runtime dependency", path: "package.json", before: PKG({ express: "^4.19.0" }), after: PKG({ express: "^4.19.0", axios: "^1.7.0" }), expect: ["new-dependency"] },
  { name: "package.json: a new optional dependency", path: "package.json", before: PKG({ express: "^4.19.0" }), after: JSON.stringify({ name: "svc", dependencies: { express: "^4.19.0" }, optionalDependencies: { "fsevents": "^2.3.0" } }, null, 2), expect: ["new-dependency"] },
  { name: "requirements.txt: a new package", path: "requirements.txt", before: "flask==3.0.0\nrequests>=2.31\n", after: "flask==3.0.0\nrequests>=2.31\nboto3==1.34.0\n", expect: ["new-dependency"] },
  { name: "requirements-prod.txt: a new package with extras", path: "requirements-prod.txt", before: "flask==3.0.0\n", after: "flask==3.0.0\nuvicorn[standard]==0.30.0\n", expect: ["new-dependency"] },
  { name: "pyproject: a new [project] dependency", path: "pyproject.toml", before: `[project]\nname = "svc"\ndependencies = [\n  "httpx>=0.27",\n]\n`, after: `[project]\nname = "svc"\ndependencies = [\n  "httpx>=0.27",\n  "stripe>=9.0",\n]\n`, expect: ["new-dependency"] },
  { name: "pyproject: a new poetry dependency", path: "pyproject.toml", before: `[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "^0.27"\n`, after: `[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "^0.27"\nredis = "^5.0"\n`, expect: ["new-dependency"] },
  { name: "go.mod: a new require in the block", path: "go.mod", before: "module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/go-chi/chi/v5 v5.0.12\n)\n", after: "module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/go-chi/chi/v5 v5.0.12\n\tgithub.com/aws/aws-sdk-go-v2 v1.30.0\n)\n", expect: ["new-dependency"] },
  { name: "Cargo.toml: a new crate", path: "Cargo.toml", before: `[package]\nname = "svc"\n\n[dependencies]\nserde = "1"\n`, after: `[package]\nname = "svc"\n\n[dependencies]\nserde = "1"\nreqwest = { version = "0.12", features = ["json"] }\n`, expect: ["new-dependency"] },
  { name: "Gemfile: a new gem", path: "Gemfile", before: `source "https://rubygems.org"\ngem "rails", "~> 7.1"\n`, after: `source "https://rubygems.org"\ngem "rails", "~> 7.1"\ngem "faraday"\n`, expect: ["new-dependency"] },
  { name: "pom.xml: a new compile dependency", path: "pom.xml", before: "<project><dependencies>\n<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>\n</dependencies></project>\n", after: "<project><dependencies>\n<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>\n<dependency><groupId>com.squareup.okhttp3</groupId><artifactId>okhttp</artifactId><version>4.12.0</version></dependency>\n</dependencies></project>\n", expect: ["new-dependency"] },
  { name: "build.gradle.kts: a new implementation dependency", path: "build.gradle.kts", before: `dependencies {\n    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")\n}\n`, after: `dependencies {\n    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")\n    implementation("io.ktor:ktor-client-core:2.3.11")\n}\n`, expect: ["new-dependency"] },
  // ---- new-egress-host ----
  { name: "python: a new outbound host", path: "app/billing/client.py", before: CLIENT_PY, after: CLIENT_PY.replace('BASE = ', 'FX = "https://api.exchangerates.example-fx.com/latest"\nBASE = '), expect: ["new-egress-host"] },
  { name: "js: fetch to a new host", path: "src/notify.js", before: `export async function ping() {\n  return fetch("https://hooks.slack.com/services/x");\n}\n`, after: `export async function ping() {\n  await fetch("https://telemetry.vendor-metrics.io/v1/events", { method: "POST" });\n  return fetch("https://hooks.slack.com/services/x");\n}\n`, expect: ["new-egress-host"] },
  { name: "yaml config: a new endpoint host", path: "config/production.yaml", before: "payments:\n  endpoint: https://api.stripe.com/v1\n", after: "payments:\n  endpoint: https://api.stripe.com/v1\nsearch:\n  url: https://search.partner-cloud.net/query\n", expect: ["new-egress-host"] },
  { name: "go: a new host in a new file", path: "internal/geo/lookup.go", before: null, after: `package geo\n\nconst api = "https://ipinfo.io/json"\n`, expect: ["new-egress-host"] },
  // ---- new-credential-path ----
  { name: "js: a new secret env var read", path: "src/payments.js", before: `const port = process.env.PORT;\n`, after: `const port = process.env.PORT;\nconst key = process.env.STRIPE_SECRET_KEY;\n`, expect: ["new-credential-path"] },
  { name: "python: os.getenv of a new token", path: "worker/sync.py", before: "import os\nREGION = os.getenv('AWS_REGION')\n", after: "import os\nREGION = os.getenv('AWS_REGION')\nTOKEN = os.getenv('GITHUB_TOKEN')\n", expect: ["new-credential-path"] },
  { name: "go: os.Getenv of a password", path: "cmd/db/main.go", before: `package main\n\nimport "os"\n\nfunc host() string { return os.Getenv("DB_HOST") }\n`, after: `package main\n\nimport "os"\n\nfunc host() string { return os.Getenv("DB_HOST") }\nfunc pw() string { return os.Getenv("DB_PASSWORD") }\n`, expect: ["new-credential-path"] },
  { name: "python: a new credential file path", path: "deploy/upload.py", before: "import boto3\n", after: "import boto3\nsession = boto3.Session(profile_name='ci')\nCREDS = '~/.aws/credentials'\n", expect: ["new-credential-path"] },
  { name: "js: dotenv loading added", path: "src/index.js", before: `import express from "express";\n`, after: `import "dotenv/config";\nimport express from "express";\n`, expect: ["new-credential-path"] },
  { name: ".env: a new key", path: ".env", before: "PORT=3000\n", after: "PORT=3000\nSENDGRID_API_KEY=placeholder\n", expect: ["new-credential-path"] },
  // ---- new-route ----
  { name: "express: a new route", path: "src/server.js", before: SERVER_JS, after: SERVER_JS.replace('app.listen', 'app.post("/admin/export", exportAll);\napp.listen'), expect: ["new-route"] },
  { name: "express router: a new route", path: "src/routes/orders.ts", before: `const router = Router();\nrouter.get("/orders", list);\nexport default router;\n`, after: `const router = Router();\nrouter.get("/orders", list);\nrouter.delete("/orders/:id", remove);\nexport default router;\n`, expect: ["new-route"] },
  { name: "fastify: route object", path: "src/app.js", before: `fastify.get("/", root);\n`, after: `fastify.get("/", root);\nfastify.route({ method: "POST", url: "/webhook", handler: hook });\n`, expect: ["new-route"] },
  { name: "flask: a new decorator route", path: "app/views.py", before: `@app.route("/")\ndef index():\n    return "ok"\n`, after: `@app.route("/")\ndef index():\n    return "ok"\n\n@app.route("/debug/env")\ndef env():\n    return dict(os.environ)\n`, expect: ["new-route"] },
  { name: "fastapi: a new router endpoint", path: "api/items.py", before: `@router.get("/items")\nasync def items():\n    return []\n`, after: `@router.get("/items")\nasync def items():\n    return []\n\n@router.post("/items/import")\nasync def imp():\n    return {}\n`, expect: ["new-route"] },
  { name: "django: a new urlpattern", path: "shop/urls.py", before: `urlpatterns = [\n    path("cart/", views.cart),\n]\n`, after: `urlpatterns = [\n    path("cart/", views.cart),\n    path("internal/dump/", views.dump),\n]\n`, expect: ["new-route"] },
  { name: "go net/http: a new HandleFunc", path: "cmd/api/main.go", before: `func main() {\n\thttp.HandleFunc("/healthz", health)\n}\n`, after: `func main() {\n\thttp.HandleFunc("/healthz", health)\n\thttp.HandleFunc("/upload", upload)\n}\n`, expect: ["new-route"] },
  { name: "spring: a new mapping", path: "src/main/java/com/acme/AdminController.java", before: `@RestController\npublic class AdminController {\n  @GetMapping("/status")\n  public String status() { return "ok"; }\n}\n`, after: `@RestController\npublic class AdminController {\n  @GetMapping("/status")\n  public String status() { return "ok"; }\n  @PostMapping("/admin/reset")\n  public String reset() { return "done"; }\n}\n`, expect: ["new-route"] },
  { name: "rails: a new resource route", path: "config/routes.rb", before: `Rails.application.routes.draw do\n  resources :posts\nend\n`, after: `Rails.application.routes.draw do\n  resources :posts\n  post "webhooks/stripe", to: "webhooks#stripe"\nend\n`, expect: ["new-route"] }
];

export const BENIGN_EDITS = [
  // bumping an existing dependency
  { name: "package.json: version bump", path: "package.json", before: PKG({ express: "^4.19.0", axios: "^1.6.0" }), after: PKG({ express: "^4.19.0", axios: "^1.7.2" }) },
  { name: "package.json: a new devDependency", path: "package.json", before: PKG({ express: "^4.19.0" }), after: PKG({ express: "^4.19.0" }, { vitest: "^2.0.0" }) },
  { name: "package.json: a new script only", path: "package.json", before: PKG({ express: "^4.19.0" }), after: PKG({ express: "^4.19.0" }).replace('"test": "node --test"', '"test": "node --test",\n    "lint": "eslint ."') },
  { name: "requirements.txt: pin bump", path: "requirements.txt", before: "flask==3.0.0\nrequests>=2.31\n", after: "flask==3.0.3\nrequests>=2.32\n" },
  { name: "requirements.txt: comment added", path: "requirements.txt", before: "flask==3.0.0\n", after: "# web framework\nflask==3.0.0\n" },
  { name: "go.mod: version bump", path: "go.mod", before: "module m\n\nrequire github.com/go-chi/chi/v5 v5.0.11\n", after: "module m\n\nrequire github.com/go-chi/chi/v5 v5.0.12\n" },
  { name: "Cargo.toml: a new dev-dependency", path: "Cargo.toml", before: `[dependencies]\nserde = "1"\n`, after: `[dependencies]\nserde = "1"\n\n[dev-dependencies]\nproptest = "1"\n` },
  { name: "Cargo.toml: version bump", path: "Cargo.toml", before: `[dependencies]\nserde = "1.0.100"\n`, after: `[dependencies]\nserde = "1.0.200"\n` },
  { name: "pom.xml: a new test-scoped dependency", path: "pom.xml", before: "<project><dependencies>\n</dependencies></project>\n", after: "<project><dependencies>\n<dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><scope>test</scope></dependency>\n</dependencies></project>\n" },
  { name: "gradle: a new testImplementation", path: "build.gradle", before: `dependencies {\n}\n`, after: `dependencies {\n    testImplementation 'org.mockito:mockito-core:5.11.0'\n}\n` },
  { name: "fixture package.json: a new dependency", path: "test/fixtures/app/package.json", before: PKG({ a: "1" }), after: PKG({ a: "1", b: "1" }) },
  { name: "example package.json: a new dependency", path: "examples/demo/package.json", before: PKG({}), after: PKG({ express: "^4" }) },
  // a URL in a README or a test
  { name: "README: a new URL", path: "README.md", before: "# svc\n", after: "# svc\n\nSee https://docs.partner-cloud.net/setup for setup.\n" },
  { name: "docs page: a new URL", path: "docs/integrations.md", before: "", after: "Calls https://api.newvendor.io/v1\n" },
  { name: "test file: a new URL", path: "tests/test_client.py", before: "def test_a():\n    pass\n", after: "def test_a():\n    assert fetch('https://api.mock-service.dev/ok')\n" },
  { name: "js spec: a new URL", path: "src/client.test.js", before: "", after: `test("x", () => fetch("https://httpbin.org/get"));\n` },
  { name: "fixture JSON: a new URL", path: "test/fixtures/response.json", before: "{}", after: `{"next": "https://api.github.com/repos?page=2"}` },
  // a localhost URL
  { name: "js: a localhost URL", path: "src/dev.js", before: `const a = 1;\n`, after: `const a = 1;\nconst DEV = "http://localhost:5173/api";\n` },
  { name: "python: a 127.0.0.1 URL", path: "app/settings.py", before: "DEBUG = True\n", after: "DEBUG = True\nCACHE = 'http://127.0.0.1:6379/0'\n" },
  { name: "yaml: an example.com placeholder", path: "config/sample-settings.yaml", before: "a: 1\n", after: "a: 1\nwebhook: https://hooks.example.com/notify\n" },
  { name: "js: a URL in a comment", path: "src/util.js", before: `export const x = 1;\n`, after: `// based on https://stackoverflow.com/a/12345\nexport const x = 1;\n` },
  { name: "python: same host, new path", path: "app/billing/client.py", before: CLIENT_PY, after: CLIENT_PY.replace('BASE + "/charge"', '"https://api.billing.internal.acme.io/v2/refund"') },
  { name: "json: $schema URL", path: "tsconfig.json", before: `{"compilerOptions":{}}`, after: `{"$schema":"https://json.schemastore.org/tsconfig","compilerOptions":{}}` },
  // reading an existing env var
  { name: "js: the same secret env var read again", path: "src/payments.js", before: `const key = process.env.STRIPE_SECRET_KEY;\n`, after: `const key = process.env.STRIPE_SECRET_KEY;\nif (!process.env.STRIPE_SECRET_KEY) throw new Error("missing");\n` },
  { name: "python: a non-secret env var", path: "app/config.py", before: "import os\n", after: "import os\nPORT = int(os.environ.get('PORT', '8000'))\nLOG_LEVEL = os.getenv('LOG_LEVEL')\n" },
  { name: ".env: an existing key's value changed", path: ".env", before: "PORT=3000\nAPI_TOKEN=old\n", after: "PORT=3001\nAPI_TOKEN=new\n" },
  { name: ".env.example: a new key", path: ".env.example", before: "PORT=\n", after: "PORT=\nSENDGRID_API_KEY=\n" },
  { name: "test: a new secret env var read", path: "tests/test_auth.py", before: "import os\n", after: "import os\nTOKEN = os.environ['GITHUB_TOKEN']\n" },
  { name: "python: a cert path, not a secret", path: "app/tls.py", before: "import ssl\n", after: "import ssl\nCA = '/etc/ssl/certs/ca-bundle.pem'\n" },
  // renaming a route
  { name: "express: a route renamed", path: "src/server.js", before: SERVER_JS, after: SERVER_JS.replace('app.get("/users"', 'app.get("/members"') },
  { name: "flask: a route renamed", path: "app/views.py", before: `@app.route("/old")\ndef v():\n    pass\n`, after: `@app.route("/new")\ndef v():\n    pass\n` },
  { name: "spring: a mapping path renamed", path: "src/main/java/A.java", before: `@GetMapping("/a")\nString a() { return ""; }\n`, after: `@GetMapping("/b")\nString a() { return ""; }\n` },
  // a comment mentioning a route
  { name: "js: a comment mentioning a route", path: "src/server.js", before: SERVER_JS, after: SERVER_JS.replace('app.listen', '// TODO: app.post("/admin/export", exportAll) once auth lands\napp.listen') },
  { name: "python: a docstring mentioning a route", path: "app/views.py", before: `def v():\n    pass\n`, after: `def v():\n    """Like @app.route("/debug") but safer."""\n    pass\n` },
  { name: "go: a comment mentioning HandleFunc", path: "cmd/api/main.go", before: `func main() {}\n`, after: `// http.HandleFunc("/upload", upload) was removed\nfunc main() {}\n` },
  { name: "map.get with a path-like key", path: "src/cache.js", before: `const c = new Map();\n`, after: `const c = new Map();\nconst v = cache.get("/users");\n` },
  { name: "README: a route example", path: "README.md", before: "", after: "```js\napp.post('/admin', h)\n```\n" }
];

export const POSITIVE_COMMANDS = [
  { name: "npm install a new package", command: "npm install axios", manifests: { "package.json": PKG({ express: "^4" }) }, expect: ["new-dependency"] },
  { name: "npm i with a version, behind an env assignment", command: "CI=1 npm i left-pad@1.3.0 --save", manifests: { "package.json": PKG({}) }, expect: ["new-dependency"] },
  { name: "pnpm add", command: "pnpm add @aws-sdk/client-s3", manifests: { "package.json": PKG({}) }, expect: ["new-dependency"] },
  { name: "yarn add", command: "cd web && yarn add zod", manifests: {}, expect: ["new-dependency"] },
  { name: "pip install a new package", command: "pip install 'stripe>=9'", manifests: { "requirements.txt": "flask\n" }, expect: ["new-dependency"] },
  { name: "python -m pip install", command: "python3 -m pip install boto3", manifests: {}, expect: ["new-dependency"] },
  { name: "cargo add", command: "cargo add reqwest --features json", manifests: { "Cargo.toml": "[dependencies]\nserde = \"1\"\n" }, expect: ["new-dependency"] },
  { name: "go get", command: "go get github.com/redis/go-redis/v9@latest", manifests: { "go.mod": "module m\n" }, expect: ["new-dependency"] }
];

export const BENIGN_COMMANDS = [
  { name: "npm install with no package (restore)", command: "npm install", manifests: { "package.json": PKG({ express: "^4" }) } },
  { name: "npm ci", command: "npm ci", manifests: {} },
  { name: "npm install a dev dependency", command: "npm install -D vitest", manifests: {} },
  { name: "npm install a global tool", command: "npm install -g typescript", manifests: {} },
  { name: "npm bump an existing dependency", command: "npm install express@latest", manifests: { "package.json": PKG({ express: "^4" }) } },
  { name: "pip install -r requirements", command: "pip install -r requirements.txt", manifests: {} },
  { name: "pip install -e .", command: "pip install -e .", manifests: {} },
  { name: "pip upgrade an existing package", command: "pip install -U flask", manifests: { "requirements.txt": "Flask==3.0.0\n" } },
  { name: "cargo add a dev dependency", command: "cargo add --dev proptest", manifests: {} },
  { name: "go get -u an existing module", command: "go get -u github.com/go-chi/chi/v5", manifests: { "go.mod": "module m\n\nrequire github.com/go-chi/chi/v5 v5.0.11\n" } },
  { name: "echo mentioning npm install", command: "echo 'run npm install axios later'", manifests: {} },
  { name: "grep for an install line", command: "grep -r 'pip install' docs/", manifests: {} }
];
