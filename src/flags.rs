use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static KNOWN_STACK_TERMS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    let terms = [
        "python",
        "javascript",
        "typescript",
        "rust",
        "golang",
        "java",
        "csharp",
        "ruby",
        "php",
        "swift",
        "kotlin",
        "scala",
        "elixir",
        "clojure",
        "haskell",
        "lua",
        "perl",
        "zig",
        "nim",
        "dart",
        "fastapi",
        "django",
        "flask",
        "express",
        "nextjs",
        "nuxtjs",
        "remix",
        "svelte",
        "sveltekit",
        "angular",
        "react",
        "vue",
        "astro",
        "gatsby",
        "rails",
        "sinatra",
        "gin",
        "echo_framework",
        "actix",
        "axum",
        "rocket",
        "spring",
        "quarkus",
        "laravel",
        "phoenix",
        "hono",
        "elysia",
        "bun",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "sqlite",
        "mongodb",
        "redis",
        "memcached",
        "cassandra",
        "dynamodb",
        "cockroachdb",
        "supabase",
        "firebase",
        "planetscale",
        "neon",
        "turso",
        "qdrant",
        "pinecone",
        "weaviate",
        "milvus",
        "elasticsearch",
        "opensearch",
        "typesense",
        "meilisearch",
        "algolia",
        "rabbitmq",
        "nats",
        "pulsar",
        "sqs",
        "sns",
        "celery",
        "bullmq",
        "sidekiq",
        "docker",
        "kubernetes",
        "terraform",
        "ansible",
        "nginx",
        "caddy",
        "traefik",
        "envoy",
        "istio",
        "consul",
        "vault",
        "aws",
        "gcp",
        "azure",
        "vercel",
        "netlify",
        "railway",
        "flyio",
        "render",
        "heroku",
        "cloudflare",
        "digitalocean",
        "pydantic",
        "sqlalchemy",
        "prisma",
        "drizzle",
        "typeorm",
        "sequelize",
        "mongoose",
        "httpx",
        "axios",
        "requests",
        "ws",
        "socket_io",
        "graphql",
        "grpc",
        "trpc",
        "zod",
        "joi",
        "yup",
        "valibot",
        "tanstack",
        "zustand",
        "jotai",
        "redux",
        "mobx",
        "tailwind",
        "shadcn",
        "pytorch",
        "tensorflow",
        "onnx",
        "ollama",
        "openai",
        "anthropic",
        "langchain",
        "llamaindex",
        "huggingface",
        "transformers",
        "sklearn",
        "numpy",
        "pandas",
        "pytest",
        "jest",
        "vitest",
        "playwright",
        "cypress",
        "selenium",
        "mocha",
        "chai",
        "oauth",
        "jwt",
        "auth0",
        "clerk",
        "lucia",
        "nextauth",
        "github_actions",
        "gitlab_ci",
        "jenkins",
        "circleci",
        "argo",
        "flux",
        "sse",
        "websocket",
        "http2",
        "http3",
        "protobuf",
        "json",
        "yaml",
        "toml",
        "msgpack",
        "avro",
        "git",
        "npm",
        "yarn",
        "pnpm",
        "pip",
        "cargo",
        "maven",
        "gradle",
        "webpack",
        "vite",
        "esbuild",
        "rollup",
        "turbopack",
        "swc",
        "babel",
        "eslint",
        "ruff",
        "prettier",
        "biome",
        "storybook",
        "chromatic",
        "prometheus",
        "grafana",
        "datadog",
        "sentry",
        "opentelemetry",
        "jaeger",
        "zipkin",
        "pagerduty",
        "logstash",
        "fluentd",
        "stripe",
        "twilio",
        "sendgrid",
        "resend",
        "postmark",
        "s3",
        "r2",
        "minio",
        "litestream",
        "yara",
        "deberta",
        "nomic",
    ];
    for s in terms {
        set.insert(s);
    }
    set
});

// SAFETY: compile-time invariant — hardcoded regex patterns; failure indicates a bug that must not ship
static URL_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches any network-resolvable token. The user-facing approval
    // gate (wevibe-guard plugin) decides policy; we detect, we do not
    // suppress.
    Regex::new(
        r#"(?x)
        (?:
            # 1. URLs with scheme
            https?://[^\s'"<>)\]]+
          |
            # 2. Scheme-less domain with path: foo.bar.tld/something
            \b[a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+ / [^\s'"<>)\]]*
          |
            # 3. Bare hostname with TLD (requires 2-24 char alpha TLD
            #    to avoid matching "1.2.3" as hostname)
            \b[a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,24}\b
          |
            # 4. IPv4 literal with optional port and path
            \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:/[^\s'"<>)\]]*)?\b
        )
        "#
    ).unwrap()
});

static INSTALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)\bpip3?\s+install\s+(?:--[a-z-]+\s+)*([a-zA-Z0-9_-]+)"#).unwrap(),
        Regex::new(r#"(?i)\bnpm\s+(?:install|i)\s+(?:--[a-z-]+\s+)*([a-zA-Z0-9@/_-]+)"#).unwrap(),
        Regex::new(r#"(?i)\byarn\s+add\s+(?:--[a-z-]+\s+)*([a-zA-Z0-9@/_-]+)"#).unwrap(),
        Regex::new(r#"(?i)\bpnpm\s+(?:add|install)\s+(?:--[a-z-]+\s+)*([a-zA-Z0-9@/_-]+)"#).unwrap(),
        Regex::new(r#"(?i)\bcargo\s+add\s+([a-zA-Z0-9_-]+)"#).unwrap(),
        Regex::new(r#"(?i)\bgo\s+get\s+([a-zA-Z0-9_./-]+)"#).unwrap(),
        Regex::new(r#"(?i)\bgem\s+install\s+([a-zA-Z0-9_-]+)"#).unwrap(),
        Regex::new(r#"(?i)\bbrew\s+install\s+([a-zA-Z0-9_@/-]+)"#).unwrap(),
    ]
});

static ENDPOINT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:GET|POST|PUT|DELETE|PATCH)\s+/[a-zA-Z0-9/_-]+"#).unwrap());

static API_PATH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/(?:api|v[0-9]+)/[a-zA-Z0-9/_-]+").unwrap());

static CONFIG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\b[A-Z][A-Z0-9_]{2,}=[^\s]+").unwrap(),
        Regex::new(r"\bexport\s+[A-Z][A-Z0-9_]{2,}=").unwrap(),
        Regex::new(r"\bos\.environ\[.[A-Z][A-Z0-9_]{2,}.]").unwrap(),
        Regex::new(r"\bprocess\.env\.[A-Z][A-Z0-9_]{2,}").unwrap(),
    ]
});

static CONNECTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|sqlite|mssql)://[^\s'"]+"#,
    )
    .unwrap()
});

#[derive(Debug, Clone)]
pub struct FlagResult {
    pub flags: Vec<String>,
}

pub fn flag_action_proximate(text: &str, stack: &[&str]) -> FlagResult {
    let mut flags: Vec<String> = Vec::new();
    let mut known_pkgs: HashSet<String> = KNOWN_STACK_TERMS.iter().map(|s| s.to_string()).collect();
    for s in stack {
        known_pkgs.insert(s.to_lowercase().replace("-", "_"));
    }

    if URL_RE.is_match(text) {
        flags.push("url".to_string());
    }

    'install_loop: for pattern in INSTALL_PATTERNS.iter() {
        for caps in pattern.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                let pkg_name = m.as_str().to_lowercase().replace("-", "_");
                let pkg_clean: String = pkg_name
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !pkg_clean.is_empty() && !known_pkgs.contains(&pkg_clean) {
                    flags.push("package_install".to_string());
                    break 'install_loop;
                }
            }
        }
    }

    if ENDPOINT_RE.is_match(text) || API_PATH_RE.is_match(text) {
        flags.push("endpoint".to_string());
    }

    for pattern in CONFIG_PATTERNS.iter() {
        if pattern.is_match(text) {
            flags.push("config".to_string());
            break;
        }
    }

    if CONNECTION_RE.is_match(text) {
        flags.push("connection_string".to_string());
    }

    flags.sort();
    flags.dedup();
    FlagResult { flags }
}
