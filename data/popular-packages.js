// T1-2 (#62) — offline slopsquat / typosquat classifier. Content-free and fully on-device: it reasons
// only about package NAMES (never file/prompt content) against a bundled curated list of the most-
// typosquatted popular packages + a list of documented malicious/hallucinated names. This is the
// high-value core (attackers squat POPULAR names); a full "does this name exist in the registry?"
// Bloom filter over the entire npm/PyPI/crates index is a separate data-pipeline follow-up.
//
// Sources for the lists: Socket (2026 slopsquatting-targets + payment-SDK campaign), USENIX 2025
// package-hallucination study, Lasso Security (huggingface-cli), SentinelOne (rustdecimal), Bertus 2018.

export const POPULAR_PACKAGES = {
  npm: ["react","react-dom","express","lodash","axios","chalk","commander","debug","next","vue","@angular/core","typescript","webpack","@babel/core","eslint","prettier","jest","mocha","chai","moment","dayjs","uuid","dotenv","cors","body-parser","mongoose","sequelize","pg","mysql2","redis","socket.io","ws","node-fetch","cross-env","rimraf","glob","fs-extra","yargs","inquirer","request","bluebird","async","underscore","ramda","rxjs","redux","react-redux","react-router","react-router-dom","styled-components","tailwindcss","postcss","autoprefixer","sass","vite","rollup","esbuild","gulp","nodemon","pm2","winston","morgan","helmet","passport","jsonwebtoken","bcrypt","bcryptjs","crypto-js","validator","joi","yup","zod","classnames","prop-types","formik","react-hook-form","antd","@mui/material","bootstrap","jquery","d3","three","chart.js","leaflet","semver","chokidar","minimist","ejs","handlebars","marked","cheerio","puppeteer","playwright","nanoid","ms","colors","ansi-styles","supports-color","readable-stream","typeorm","graphql","@apollo/client","next-auth","swr","@tanstack/react-query","framer-motion","lucide-react","date-fns","qs","node-sass","eslint-plugin-react","@types/node","ts-node","concurrently","cross-fetch","form-data","undici","execa","dompurify","sharp"],
  pypi: ["requests","numpy","pandas","flask","django","scipy","matplotlib","pillow","urllib3","setuptools","wheel","pip","boto3","botocore","certifi","charset-normalizer","idna","six","python-dateutil","pytz","pyyaml","click","jinja2","markupsafe","werkzeug","sqlalchemy","cryptography","cffi","pycparser","attrs","packaging","typing-extensions","protobuf","grpcio","redis","celery","pytest","coverage","black","flake8","mypy","isort","pylint","tensorflow","torch","scikit-learn","keras","transformers","huggingface-hub","tokenizers","openai","anthropic","langchain","fastapi","uvicorn","starlette","pydantic","httpx","aiohttp","beautifulsoup4","lxml","selenium","scrapy","tqdm","rich","colorama","tabulate","python-dotenv","psycopg2","pymongo","asyncpg","alembic","gunicorn","websockets","jsonschema","marshmallow","opencv-python","seaborn","plotly","statsmodels","sympy","networkx","nltk","spacy","xgboost","lightgbm","joblib","dask","jellyfish","fabric"],
  crates: ["serde","serde_json","tokio","syn","quote","proc-macro2","rand","libc","regex","log","clap","anyhow","thiserror","futures","bytes","itertools","lazy_static","once_cell","chrono","uuid","reqwest","hyper","tracing","tracing-subscriber","num-traits","cfg-if","bitflags","base64","hashbrown","indexmap","parking_lot","crossbeam","rayon","async-trait","tonic","prost","actix-web","axum","tower","sqlx","diesel","hex","sha2","ring","url","semver","toml","env_logger","num_cpus","rust_decimal"]
};

// Documented malicious / hallucinated names — hard-flag on exact match. Never add these to POPULAR.
export const KNOWN_BAD_PACKAGES = new Set([
  "huggingface-cli","css-color-stop","dns-sd","dom-ains","colourama","jeillyfish","jeillyfish","python3-dateutil",
  "torchtriton","fabrice","paysafe-sdk","paysafe-payments","paysafe-api","crossenv","loadsh","lodahs","mongose",
  "twilio-npm","babelcli","noblox.js-proxy","paysafe-checkout","paysafe-node","paysafe-js","rustdecimal",
  "ethers-provider2","mumpy","openvc","diango","faster_log"
].map((s) => s.toLowerCase()));

const ALIASES = { js: "npm", javascript: "npm", node: "npm", py: "pypi", python: "pypi", pip: "pypi", rs: "crates", rust: "crates", cargo: "crates" };
const POP = { npm: new Set(POPULAR_PACKAGES.npm), pypi: new Set(POPULAR_PACKAGES.pypi), crates: new Set(POPULAR_PACKAGES.crates) };
const ALL_POP = new Set([...POP.npm, ...POP.pypi, ...POP.crates]);

// Bounded Damerau-Levenshtein: returns true if edit distance (incl. adjacent transposition) <= max.
function withinEdit(a, b, max) {
  const al = a.length, bl = b.length;
  if (Math.abs(al - bl) > max) return false;
  const d = Array.from({ length: al + 1 }, (_, i) => [i, ...Array(bl).fill(0)]);
  for (let j = 0; j <= bl; j++) d[0][j] = j;
  for (let i = 1; i <= al; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return false; // early exit — no path can still be within max
  }
  return d[al][bl] <= max;
}

// Classify a single package name for an ecosystem: "malicious" | "typosquat" | "confused" | "ok".
export function classifyPackage(name, ecosystem) {
  const n = String(name || "").toLowerCase().trim();
  if (!n || n.length < 2) return "ok";
  const eco = ALIASES[ecosystem] || ecosystem;
  if (KNOWN_BAD_PACKAGES.has(n)) return "malicious";
  const pop = POP[eco];
  if (pop && pop.has(n)) return "ok";
  // exact match to a popular name in ANOTHER ecosystem while installing here = ecosystem confusion
  if (pop && !pop.has(n) && ALL_POP.has(n)) return "confused";
  // near-miss of a popular name in this ecosystem = probable typosquat (edit distance 1, and 2 for longer names)
  if (pop) {
    const max = n.length >= 6 ? 2 : 1;
    for (const p of pop) {
      if (p === n) continue;
      if (Math.abs(p.length - n.length) > max) continue;
      if (withinEdit(n, p, max)) return "typosquat";
    }
  }
  return "ok"; // unknown name, no near-miss — not enough signal without a full registry index
}

// Extract {ecosystem, name} pairs from an install command. Content-free (parses the command string).
export function extractInstalls(command) {
  const c = String(command || "");
  const out = [];
  const add = (eco, names) => { for (const raw of names) { const nm = cleanName(raw); if (nm) out.push({ ecosystem: eco, name: nm }); } };
  let m;
  const npmRe = /\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|i)\b([^\n&|;]*)/gi;
  while ((m = npmRe.exec(c))) add("npm", tokens(m[1]));
  const pipRe = /\b(?:pip3?|pipx|uv\s+pip|python3?\s+-m\s+pip)\s+install\b([^\n&|;]*)/gi;
  while ((m = pipRe.exec(c))) add("pypi", tokens(m[1]));
  const cargoRe = /\bcargo\s+(?:add|install)\b([^\n&|;]*)/gi;
  while ((m = cargoRe.exec(c))) add("crates", tokens(m[1]));
  return out;
}

function tokens(s) { return String(s || "").trim().split(/\s+/).filter((t) => t && !t.startsWith("-")); }
function cleanName(raw) {
  // strip version/extras/markers: name==1.2, name@^1, name[extra], name>=2, git+... URLs are skipped
  let n = String(raw).trim();
  if (/^(git\+|https?:|file:|github:|\.|\/)/i.test(n)) return null;
  n = n.replace(/[[<>=!~^].*$/, "").replace(/@[^/].*$/, (mm) => (n.startsWith("@") ? mm : "")).replace(/@\d.*$/, "");
  return n.toLowerCase();
}

// Does an install command reference a malicious/typosquat/confused package? Returns the worst finding.
export function inspectInstall(command) {
  let worst = null;
  for (const { ecosystem, name } of extractInstalls(command)) {
    const verdict = classifyPackage(name, ecosystem);
    if (verdict !== "ok") { const rank = { malicious: 3, typosquat: 2, confused: 1 }; if (!worst || rank[verdict] > rank[worst.verdict]) worst = { name, ecosystem, verdict }; }
  }
  return worst;
}
