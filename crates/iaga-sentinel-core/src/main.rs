use std::env;
use std::process;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use iaga_sentinel::config::env::{load_env, load_logging_env, LogFormat, LoggingEnv};
use iaga_sentinel::core::types::RateLimitConfig;
use iaga_sentinel::events::bus::EventBus;
use iaga_sentinel::events::webhooks::{self, WebhookManager};
use iaga_sentinel::modules::fingerprint::behavioral::BehavioralEngine;
use iaga_sentinel::modules::rate_limit::limiter::RateLimiter;
use iaga_sentinel::modules::threat_intel::feed::ThreatFeed;
use iaga_sentinel::pipeline::reasoning::try_build_reasoning_engine;
use iaga_sentinel::pipeline::receipts::try_build_receipt_logger;
use iaga_sentinel::plugins::{LoadedPlugin, PluginRegistry};
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::server::create_server::create_router;
#[cfg(feature = "postgres")]
use iaga_sentinel::storage::postgres::PostgresStorage;
#[cfg(feature = "sqlite")]
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{
    ApiKeyStore, AuditStore, FingerprintStore, NhiStore, PolicyStore, RateLimitStore, ReviewStore,
    SessionStore, StorageBackend, TaintStore, TenantStore,
};

struct StorageBundle {
    audit_store: Arc<dyn AuditStore>,
    review_store: Arc<dyn ReviewStore>,
    policy_store: Arc<dyn PolicyStore>,
    api_key_store: Arc<dyn ApiKeyStore>,
    tenant_store: Arc<dyn TenantStore>,
    // v0.4.0, Durable State stores
    nhi_store: Arc<dyn NhiStore>,
    session_store: Arc<dyn SessionStore>,
    taint_store: Arc<dyn TaintStore>,
    fingerprint_store: Arc<dyn FingerprintStore>,
    rate_limit_store: Arc<dyn RateLimitStore>,
    storage_backend: StorageBackend,
}

fn detect_storage_backend(db_url: &str) -> StorageBackend {
    if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
        StorageBackend::Postgres
    } else {
        StorageBackend::Sqlite
    }
}

async fn init_storage_bundle(db_url: &str) -> Result<StorageBundle, String> {
    match detect_storage_backend(db_url) {
        StorageBackend::Sqlite => {
            #[cfg(feature = "sqlite")]
            {
                let storage = Arc::new(
                    SqliteStorage::new(db_url)
                        .await
                        .map_err(|e| format!("Failed to initialize SQLite database: {e}"))?,
                );

                Ok(StorageBundle {
                    audit_store: storage.clone(),
                    review_store: storage.clone(),
                    policy_store: storage.clone(),
                    api_key_store: storage.clone(),
                    tenant_store: storage.clone(),
                    nhi_store: storage.clone(),
                    session_store: storage.clone(),
                    taint_store: storage.clone(),
                    fingerprint_store: storage.clone(),
                    rate_limit_store: storage,
                    storage_backend: StorageBackend::Sqlite,
                })
            }

            #[cfg(not(feature = "sqlite"))]
            {
                Err("SQLite support is not compiled in this build".to_string())
            }
        }
        StorageBackend::Postgres => {
            #[cfg(feature = "postgres")]
            {
                let storage = Arc::new(
                    PostgresStorage::new(db_url)
                        .await
                        .map_err(|e| format!("Failed to initialize PostgreSQL database: {e}"))?,
                );

                Ok(StorageBundle {
                    audit_store: storage.clone(),
                    review_store: storage.clone(),
                    policy_store: storage.clone(),
                    api_key_store: storage.clone(),
                    tenant_store: storage.clone(),
                    nhi_store: storage.clone(),
                    session_store: storage.clone(),
                    taint_store: storage.clone(),
                    fingerprint_store: storage.clone(),
                    rate_limit_store: storage,
                    storage_backend: StorageBackend::Postgres,
                })
            }

            #[cfg(not(feature = "postgres"))]
            {
                Err("PostgreSQL support requires building with `--features postgres`".to_string())
            }
        }
    }
}

/// IAGA Sentinel: EU AI Act conformity evidence layer for AI agents
#[derive(Parser)]
#[command(name = "iaga-sentinel", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Database URL (overrides DATABASE_URL env var)
    #[arg(long, global = true)]
    db: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the governance server (default if no subcommand)
    Serve {
        /// Port to listen on (overrides PORT env var)
        #[arg(short, long)]
        port: Option<u16>,

        /// Seed demo data on first boot
        #[arg(long, default_value_t = true)]
        seed_demo: bool,

        /// 1.0 M6, load a Dictum policy file as an overlay on top of YAML.
        /// Stricter wins: Dictum can tighten the verdict, never relax it.
        #[cfg(feature = "dictum")]
        #[arg(long, value_name = "FILE")]
        policy: Option<String>,
    },

    /// Inspect a single payload through the governance pipeline
    Inspect {
        /// Path to JSON payload file, or --stdin
        source: String,
    },

    /// Validate a policy YAML/JSON config file without starting the server
    Validate {
        /// Path to policy config file (YAML or JSON)
        config: String,
    },

    /// Inspect and validate WASM plugins
    Plugins {
        #[command(subcommand)]
        command: PluginCommands,
    },

    /// Run database migrations
    Migrate,

    /// Import policies from a YAML/JSON config file into the database
    Import {
        /// Path to policy config file (YAML or JSON)
        config: String,
    },

    /// Export current policies from the database to YAML
    Export {
        /// Output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate a new API key
    #[command(name = "gen-key")]
    GenKey {
        /// Label for the API key
        #[arg(short, long, default_value = "cli-generated")]
        label: String,

        /// Key scope: `admin` (full access, default) or `agent`
        /// (governance surface only — cannot manage keys/webhooks/config)
        #[arg(long, default_value = "admin", value_parser = ["admin", "agent"])]
        scope: String,
    },

    /// Show audit trail
    Audit {
        /// Max number of events to show
        #[arg(short, long, default_value_t = 50)]
        limit: u32,

        /// Output format: json or table
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Show LLM cost / spend (requires the `cost-control` feature)
    #[cfg(feature = "cost-control")]
    Cost {
        /// View: summary | by-model | by-agent | by-tool | budget
        #[arg(default_value = "summary")]
        view: String,
        /// Lower time bound (RFC3339)
        #[arg(long)]
        from: Option<String>,
        /// Upper time bound (RFC3339)
        #[arg(long)]
        to: Option<String>,
        /// Max rows for by-* views
        #[arg(short, long, default_value_t = 20)]
        limit: u32,
    },

    /// Run as MCP proxy: intercept tool calls between MCP client and downstream server
    Proxy {
        /// Agent ID for governance checks
        #[arg(short, long)]
        agent_id: String,

        /// Downstream MCP server command (e.g. "npx -y @modelcontextprotocol/server-filesystem")
        #[arg(short, long)]
        command: String,

        /// Arguments for the downstream command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Run as MCP server: expose IAGA Sentinel governance tools over stdio
    McpServer {
        /// Seed demo data on startup so inspect calls work out of the box
        #[arg(long, default_value_t = true)]
        seed_demo: bool,
    },

    /// Health-check an MCP endpoint: drive initialize + tools/list, check each
    /// tool's inputSchema, optionally probe one tool, and report which calls the
    /// governance pipeline would allow/review/block. Cooperative diagnostics
    /// only (is_authoritative:false). NOTE: the governance check runs the real
    /// pipeline and writes a signed receipt per listed tool, so this is not a
    /// pure read against the receipt store.
    McpDoctor {
        /// Agent ID the governance checks are attributed to
        #[arg(short, long, default_value = "iaga-doctor")]
        agent_id: String,

        /// MCP server command to launch over stdio
        #[arg(short, long)]
        command: String,

        /// Actually call this one tool with empty arguments
        #[arg(long)]
        probe_tool: Option<String>,

        /// Output format: table or json
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Arguments for the MCP server command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// 1.0 M3, work with .dictum policy files (parse, validate, dry-run)
    #[cfg(feature = "dictum")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// 1.0 M3.5, inspect the configured probabilistic reasoning engine
    #[cfg(feature = "reasoning")]
    Reasoning {
        #[command(subcommand)]
        command: ReasoningCommands,
    },

    /// 1.0 M4, launch a child process under the enforcement kernel
    #[cfg(feature = "kernel")]
    Run {
        /// Agent identity that owns the launched process for governance purposes
        #[arg(short, long, default_value = "cli-runner")]
        agent_id: String,

        /// Optional working directory for the child
        #[arg(long)]
        cwd: Option<String>,

        /// Program to execute, followed by its arguments after `--`
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// 1.0 M4, show kernel backend status
    #[cfg(feature = "kernel")]
    Kernel {
        #[command(subcommand)]
        command: KernelCommands,
    },

    /// 1.0 M2, verify or replay a signed receipt chain for a run_id
    #[cfg(feature = "receipts")]
    Replay {
        /// run_id (event_id in M2) whose receipts should be inspected
        run_id: Option<String>,

        /// Only verify signatures and hash-chain links; no drift check
        #[arg(long, default_value_t = false)]
        verify_only: bool,

        /// List known runs instead of replaying one
        #[arg(long, default_value_t = false)]
        list: bool,

        /// Max runs to list
        #[arg(long, default_value_t = 20)]
        limit: u32,

        /// 1.2: surface drift-replay capture data and report
        /// divergence between stored and reconstructed inputs. Mutex
        /// with --verify-only. Requires receipts produced with
        /// IAGA_SENTINEL_RECEIPT_CAPTURE=1 on the source pipeline.
        #[arg(long = "re-execute", default_value_t = false)]
        re_execute: bool,

        /// Export the run's signed receipt chain to a JSON file for offline
        /// verification with the standalone `iaga-verify` tool.
        #[arg(long, value_name = "FILE")]
        export: Option<String>,
    },
}

#[cfg(feature = "dictum")]
#[derive(Subcommand)]
enum PolicyCommands {
    /// Parse, validate and optionally dry-run an .dictum file.
    Test {
        /// Path to the .dictum source file
        path: String,

        /// Optional JSON file providing the evaluation context
        /// (`action`, `workspace`, etc.). When omitted, only parse+validate run.
        #[arg(long)]
        context: Option<String>,
    },
    /// Lint an .dictum file: parse + validate only, no execution.
    /// 1.0 M6, semantic alias for `iaga policy test <file>` without --context.
    Lint {
        /// Path to the .dictum source file
        path: String,
    },
    /// 1.2 OSS, type-check (Hindley-Milner) an .dictum file.
    /// Reports per-policy `when`-clause types and any type errors
    /// (mismatch, occurs-check, builtin arity, non-bool when).
    Check {
        /// Path to the .dictum source file
        path: String,
    },
    /// 1.2 OSS, compile an .dictum file to a WebAssembly module
    /// (literal + boolean / numeric / comparison ops only; rejects
    /// Path / Call / Membership in the MVP 1.2 scope, see ADR 0014).
    Compile {
        /// Path to the .dictum source file
        path: String,

        /// Path to write the WASM module bytes. Defaults to
        /// `<path>.wasm`.
        #[arg(long)]
        output: Option<String>,
    },
}

#[cfg(feature = "reasoning")]
#[derive(Subcommand)]
enum ReasoningCommands {
    /// Print engine name and loaded model digests.
    Info,
}

#[cfg(feature = "kernel")]
#[derive(Subcommand)]
enum KernelCommands {
    /// Print backend name and whether enforcement is authoritative.
    Status,
}

#[derive(Subcommand)]
enum PluginCommands {
    /// List plugins discovered in a directory
    List {
        /// Plugin directory (defaults to IAGA_SENTINEL_PLUGIN_DIR or ./plugins)
        #[arg(long)]
        dir: Option<String>,

        /// Output format: json or table
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Validate a single WASM plugin file
    Validate {
        /// Path to the plugin .wasm file
        path: String,

        /// Output format: json or table
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// 1.2: Offline Sigstore + SBOM attestation verify. Looks for
    /// sibling <plugin>.sigstore.json and <plugin>.cdx.json files,
    /// confirms the bundle is well-formed and the payload digest
    /// matches the plugin bytes. Does NOT verify Rekor inclusion
    /// proof or Fulcio root trust (out of OSS scope per ADR 0013).
    #[cfg(feature = "plugin-attestation")]
    Verify {
        /// Path to the plugin .wasm file
        path: String,

        /// Output format: json or table
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Sign a plugin manifest (plugin sha256 + identity) with the local
    /// Ed25519 signer, writing <plugin>.manifest.json and .manifest.json.sig.
    #[cfg(feature = "plugin-manifest-signing")]
    SignManifest {
        /// Path to the plugin .wasm file
        path: String,

        /// Signer key file (defaults to IAGA_SENTINEL_SIGNER_KEY_PATH or
        /// ~/.iaga-sentinel/keys/receipt_signer.ed25519)
        #[arg(long)]
        key: Option<String>,

        /// Plugin name recorded in the manifest
        #[arg(long, default_value = "plugin")]
        name: String,

        /// Plugin version recorded in the manifest
        #[arg(long, default_value = "0.0.0")]
        version: String,
    },

    /// Verify a plugin's signed manifest against a file of trusted Ed25519
    /// public keys (hex, whitespace-separated). Checks the plugin sha256
    /// and the signature. Exit 0 verified, 1 not verified.
    #[cfg(feature = "plugin-manifest-signing")]
    VerifyManifest {
        /// Path to the plugin .wasm file
        path: String,

        /// File of trusted public keys, hex, one per line
        #[arg(long = "trusted-keys", value_name = "FILE")]
        trusted_keys: String,
    },

    /// Generate an OFFLINE in-toto/SLSA provenance attestation for a plugin.
    /// Emits an in-toto Statement (SLSA Provenance v1 predicate) over the
    /// plugin's SHA-256; with --sign, wraps it in an Ed25519 DSSE envelope. The
    /// SLSA level is recorded as operator-DECLARED build intent, NOT a verified
    /// guarantee — offline OSS cannot attest hermeticity. Rekor inclusion /
    /// Fulcio keyless identity remain Enterprise (ADR 0010/0013).
    #[cfg(feature = "plugin-manifest-signing")]
    Attest {
        /// Path to the plugin .wasm file
        path: String,

        /// Declared SLSA build level (1-4), recorded as declared intent
        #[arg(long, default_value_t = 1)]
        slsa_level: u8,

        /// Wrap the statement in a DSSE envelope signed with the local signer
        #[arg(long, default_value_t = false)]
        sign: bool,

        /// Signer key file (with --sign). Defaults to IAGA_SENTINEL_SIGNER_KEY_PATH
        /// or ~/.iaga-sentinel/keys/receipt_signer.ed25519
        #[arg(long)]
        key: Option<String>,

        /// Output file (default: <plugin>.intoto.json, or .intoto.dsse.json signed)
        #[arg(long)]
        out: Option<String>,

        /// Plugin name recorded as the statement subject
        #[arg(long, default_value = "plugin")]
        name: String,

        /// Plugin version recorded as the statement subject
        #[arg(long, default_value = "0.0.0")]
        version: String,
    },
}

#[tokio::main]
async fn main() {
    let runtime_env = load_env();
    let logging_env = load_logging_env(runtime_env.node_env);
    init_tracing(&logging_env);

    tracing::debug!(
        format = %logging_env.format,
        filter = %logging_env.filter_directive,
        "tracing initialized"
    );

    let cli = Cli::parse();
    let db_url = cli
        .db
        .clone()
        .or_else(|| env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| "sqlite:iaga_sentinel.db?mode=rwc".into());

    match cli.command {
        None | Some(Commands::Serve { .. }) => {
            #[cfg(feature = "dictum")]
            let (port_override, seed_demo, policy_path) = match &cli.command {
                Some(Commands::Serve {
                    port,
                    seed_demo,
                    policy,
                    ..
                }) => (*port, *seed_demo, policy.clone()),
                _ => (None, true, None),
            };
            #[cfg(not(feature = "dictum"))]
            let (port_override, seed_demo) = match &cli.command {
                Some(Commands::Serve {
                    port, seed_demo, ..
                }) => (*port, *seed_demo),
                _ => (None, true),
            };
            cmd_serve(
                &db_url,
                port_override,
                seed_demo,
                #[cfg(feature = "dictum")]
                policy_path.as_deref(),
            )
            .await;
        }
        Some(Commands::Inspect { source }) => {
            let code = cmd_inspect(&source, &db_url).await;
            process::exit(code);
        }
        Some(Commands::Validate { config }) => {
            cmd_validate(&config);
        }
        Some(Commands::Plugins { command }) => match command {
            PluginCommands::List { dir, format } => {
                cmd_plugins_list(dir.as_deref(), &format);
            }
            PluginCommands::Validate { path, format } => {
                cmd_plugins_validate(&path, &format);
            }
            #[cfg(feature = "plugin-attestation")]
            PluginCommands::Verify { path, format } => {
                cmd_plugins_verify(&path, &format);
            }
            #[cfg(feature = "plugin-manifest-signing")]
            PluginCommands::SignManifest {
                path,
                key,
                name,
                version,
            } => {
                let code = cmd_plugins_sign_manifest(&path, key.as_deref(), &name, &version);
                process::exit(code);
            }
            #[cfg(feature = "plugin-manifest-signing")]
            PluginCommands::VerifyManifest { path, trusted_keys } => {
                let code = cmd_plugins_verify_manifest(&path, &trusted_keys);
                process::exit(code);
            }
            #[cfg(feature = "plugin-manifest-signing")]
            PluginCommands::Attest {
                path,
                slsa_level,
                sign,
                key,
                out,
                name,
                version,
            } => {
                let code = cmd_plugins_attest(
                    &path,
                    slsa_level,
                    sign,
                    key.as_deref(),
                    out.as_deref(),
                    &name,
                    &version,
                );
                process::exit(code);
            }
        },
        Some(Commands::Migrate) => {
            cmd_migrate(&db_url).await;
        }
        Some(Commands::Import { config }) => {
            cmd_import(&config, &db_url).await;
        }
        Some(Commands::Export { output }) => {
            cmd_export(&db_url, output.as_deref()).await;
        }
        Some(Commands::GenKey { label, scope }) => {
            cmd_gen_key(&db_url, &label, &scope).await;
        }
        Some(Commands::Audit { limit, format }) => {
            cmd_audit(&db_url, limit, &format).await;
        }
        #[cfg(feature = "cost-control")]
        Some(Commands::Cost {
            view,
            from,
            to,
            limit,
        }) => {
            cmd_cost(&db_url, &view, from.as_deref(), to.as_deref(), limit).await;
        }
        Some(Commands::Proxy {
            agent_id,
            command,
            args,
        }) => {
            cmd_proxy(&db_url, &agent_id, &command, args).await;
        }
        Some(Commands::McpServer { seed_demo }) => {
            cmd_mcp_server(&db_url, seed_demo).await;
        }
        Some(Commands::McpDoctor {
            agent_id,
            command,
            probe_tool,
            format,
            args,
        }) => {
            let code =
                cmd_mcp_doctor(&db_url, &agent_id, &command, args, probe_tool, &format).await;
            process::exit(code);
        }
        #[cfg(feature = "dictum")]
        Some(Commands::Policy { command }) => match command {
            PolicyCommands::Test { path, context } => {
                let code = cmd_policy_test(&path, context.as_deref());
                process::exit(code);
            }
            PolicyCommands::Lint { path } => {
                let code = cmd_policy_test(&path, None);
                process::exit(code);
            }
            PolicyCommands::Check { path } => {
                let code = cmd_policy_check(&path);
                process::exit(code);
            }
            PolicyCommands::Compile { path, output } => {
                let code = cmd_policy_compile(&path, output.as_deref());
                process::exit(code);
            }
        },
        #[cfg(feature = "reasoning")]
        Some(Commands::Reasoning { command }) => match command {
            ReasoningCommands::Info => {
                cmd_reasoning_info();
            }
        },
        #[cfg(feature = "kernel")]
        Some(Commands::Run { agent_id, cwd, cmd }) => {
            let code = cmd_kernel_run(&db_url, &agent_id, cwd.as_deref(), &cmd).await;
            process::exit(code);
        }
        #[cfg(feature = "kernel")]
        Some(Commands::Kernel { command }) => match command {
            KernelCommands::Status => cmd_kernel_status(),
        },
        #[cfg(feature = "receipts")]
        Some(Commands::Replay {
            run_id,
            verify_only,
            list,
            limit,
            re_execute,
            export,
        }) => {
            if verify_only && re_execute {
                eprintln!("iaga replay: --verify-only and --re-execute are mutually exclusive");
                process::exit(2);
            }
            let code = cmd_replay(
                &db_url,
                run_id.as_deref(),
                verify_only,
                list,
                limit,
                re_execute,
                export.as_deref(),
            )
            .await;
            process::exit(code);
        }
    }
}

fn init_tracing(logging_env: &LoggingEnv) {
    let env_filter = tracing_subscriber::EnvFilter::try_new(&logging_env.filter_directive)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    match logging_env.format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                // Logs go to stderr, never stdout: the stdio MCP commands
                // (`mcp-server`, `proxy`, `mcp-doctor`) use stdout as the
                // JSON-RPC channel, and a log line on stdout would corrupt the
                // protocol for any MCP client.
                .with_writer(std::io::stderr)
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::fmt()
                .compact()
                .with_writer(std::io::stderr)
                .with_env_filter(env_filter)
                .with_target(true)
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .pretty()
                .with_writer(std::io::stderr)
                .with_env_filter(env_filter)
                .with_target(true)
                .init();
        }
    }
}

// ── serve ──

fn print_banner(port: u16) {
    let green = "\x1b[38;2;0;255;136m";
    let cyan = "\x1b[38;2;0;212;255m";
    let dim = "\x1b[38;2;102;102;102m";
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    let bar = "═".repeat(44);
    eprintln!("{green}{bold}");
    eprintln!("    ╔{bar}╗");
    eprintln!("    ║{:^44}║", "");
    eprintln!("    ║{:^44}║", "I A G A   S E N T I N E L");
    eprintln!("    ║{:^44}║", "");
    eprintln!("    ╚{bar}╝{reset}");
    eprintln!();
    eprintln!("    {cyan}EU AI Act conformity evidence for AI agents{reset}");
    eprintln!("    {dim}v{}{reset}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("    {green}▸{reset} Port        {bold}{port}{reset}");
    eprintln!("    {green}▸{reset} Dashboard   {cyan}http://localhost:{port}{reset}");
    eprintln!("    {green}▸{reset} API         {cyan}http://localhost:{port}/v1/inspect{reset}");
    eprintln!("    {green}▸{reset} 8 Layers    {green}ARMED{reset}");
    eprintln!();
    eprintln!("    {dim}Press Ctrl+C to shut down{reset}");
    eprintln!();
}

async fn cmd_serve(
    db_url: &str,
    port_override: Option<u16>,
    seed_demo: bool,
    #[cfg(feature = "dictum")] policy_path: Option<&str>,
) {
    let mut app_env = load_env();
    if let Some(p) = port_override {
        app_env.port = p;
    }

    print_banner(app_env.port);

    let storage = match init_storage_bundle(db_url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if seed_demo {
        seed_demo_data(&storage.policy_store).await;
    }

    // Auto-import iaga-sentinel.yaml if it exists and DB is fresh
    auto_import_config(&storage.policy_store).await;

    // Make the first boot usable: without this a fresh DB with open mode off
    // answers 401 on every route until someone runs `iaga gen-key` by hand.
    bootstrap_api_key_from_env(&storage.api_key_store).await;

    let event_bus = EventBus::new(1024);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(
        webhooks::DeadLetterQueue::new(),
    )));
    let behavioral_engine = Arc::new(BehavioralEngine::new());

    // ═══════════════════════════════════════════════════════════════
    // v0.4.0, Startup hydration: load persisted state into memory
    // ═══════════════════════════════════════════════════════════════
    {
        use iaga_sentinel::modules::nhi::crypto_identity;
        use iaga_sentinel::modules::session_graph::session_dag;
        use iaga_sentinel::modules::taint::taint_tracker;

        // Hydrate NHI identities
        match storage.nhi_store.list_identities().await {
            Ok(identities) => {
                let count = identities.len();
                for identity in identities {
                    let secret = storage
                        .nhi_store
                        .get_secret_key_hex(&identity.agent_id)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    crypto_identity::hydrate_identity(identity, &secret);
                }
                if count > 0 {
                    tracing::info!(count, "hydrated NHI identities from DB");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to hydrate NHI identities"),
        }

        // Hydrate session graphs
        match storage.session_store.list_sessions().await {
            Ok(sessions) => {
                let count = sessions.len();
                for session in sessions {
                    session_dag::hydrate_session(session);
                }
                if count > 0 {
                    tracing::info!(count, "hydrated session graphs from DB");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to hydrate session graphs"),
        }

        // Hydrate taint labels (iterate sessions from DB)
        // Note: taint sessions are already loaded above, but we also
        // need to load taint labels from their dedicated store
        match storage.session_store.list_sessions().await {
            Ok(sessions) => {
                for session in &sessions {
                    match storage
                        .taint_store
                        .get_session_taint(&session.session_id)
                        .await
                    {
                        Ok(labels) if !labels.is_empty() => {
                            taint_tracker::hydrate_session_taint(&session.session_id, labels);
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to hydrate taint labels"),
        }

        // Hydrate behavioral fingerprints
        match storage.fingerprint_store.list_fingerprints().await {
            Ok(fingerprints) => {
                let count = fingerprints.len();
                for fp in fingerprints {
                    behavioral_engine.hydrate_fingerprint(fp);
                }
                if count > 0 {
                    tracing::info!(count, "hydrated behavioral fingerprints from DB");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to hydrate fingerprints"),
        }

        // Hydrate rate limit config
        match storage.rate_limit_store.load_config().await {
            Ok(Some(_config)) => {
                tracing::info!("hydrated rate limit config from DB");
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "failed to hydrate rate limit config"),
        }
    }

    // Spawn webhook delivery worker
    webhooks::spawn_webhook_worker(event_bus.clone(), webhook_manager.clone());

    // Spawn periodic TTL cleanup for session/taint data (every 5 minutes)
    // v0.4.0, also prunes durable storage in parallel
    let cleanup_nhi = storage.nhi_store.clone();
    let cleanup_session = storage.session_store.clone();
    let cleanup_taint = storage.taint_store.clone();
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(iaga_sentinel::config::env::env_parse(
            "IAGA_SENTINEL_CLEANUP_INTERVAL_SECS",
            300u64,
        ));
        let ttl_secs =
            iaga_sentinel::config::env::env_parse("IAGA_SENTINEL_CLEANUP_TTL_SECS", 3600u64);
        let ttl = std::time::Duration::from_secs(ttl_secs);
        let ttl_ms = ttl_secs.saturating_mul(1000);
        loop {
            tokio::time::sleep(interval).await;

            // Prune in-memory state
            let taint_pruned =
                iaga_sentinel::modules::taint::taint_tracker::prune_stale_sessions(ttl);
            let session_pruned =
                iaga_sentinel::modules::session_graph::session_dag::prune_stale_sessions(ttl_ms);
            let challenge_pruned =
                iaga_sentinel::modules::nhi::crypto_identity::prune_expired_challenges();

            // Prune durable storage (best-effort, log errors)
            let _ = cleanup_nhi
                .prune_expired_challenges()
                .await
                .map_err(|e| tracing::warn!(error = %e, "DB prune: NHI challenges"));
            let _ = cleanup_session
                .prune_stale_sessions(ttl_ms)
                .await
                .map_err(|e| tracing::warn!(error = %e, "DB prune: sessions"));
            let _ = cleanup_taint
                .prune_stale_sessions(ttl_secs)
                .await
                .map_err(|e| tracing::warn!(error = %e, "DB prune: taint"));

            if taint_pruned > 0 || session_pruned > 0 || challenge_pruned > 0 {
                tracing::debug!(
                    taint_pruned,
                    session_pruned,
                    challenge_pruned,
                    "TTL cleanup completed"
                );
            }
        }
    });

    // Load rate limit config from DB (if persisted), otherwise use defaults
    let rate_limit_config = storage
        .rate_limit_store
        .load_config()
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));
    let threat_feed = build_threat_feed();
    tracing::info!(
        indicators = threat_feed.get_stats().total_indicators,
        "Threat intelligence feed loaded"
    );

    // 1.0 M6: load Dictum overlay if --policy was provided. Fail-fast on any
    // load error: if the operator asked for Dictum, they want Dictum. Loaded
    // *before* the receipt logger so the bundle digest can be embedded
    // in every receipt's `policy_hash` field.
    #[cfg(feature = "dictum")]
    let dictum_overlay: Option<Arc<iaga_sentinel::pipeline::dictum_overlay::DictumOverlay>> =
        match policy_path {
            None => None,
            Some(p) => {
                use iaga_sentinel::pipeline::dictum_overlay::DictumOverlay;
                match DictumOverlay::load(std::path::Path::new(p)) {
                    Ok(o) => {
                        tracing::info!(
                            policies = o.policy_count(),
                            hash = o.policy_hash(),
                            source = %o.source_path().display(),
                            "M6: Dictum policy overlay loaded"
                        );
                        Some(Arc::new(o))
                    }
                    Err(e) => {
                        eprintln!("Dictum load failed: {}", e);
                        process::exit(2);
                    }
                }
            }
        };

    #[cfg(feature = "dictum")]
    let policy_hash_override = dictum_overlay.as_ref().map(|o| o.policy_hash().to_string());
    #[cfg(not(feature = "dictum"))]
    let policy_hash_override: Option<String> = None;

    let receipts = try_build_receipt_logger(db_url, policy_hash_override).await;
    require_receipts_or_exit(&receipts);
    let reasoning = try_build_reasoning_engine();

    let state = Arc::new(AppState {
        audit_store: storage.audit_store,
        review_store: storage.review_store,
        policy_store: storage.policy_store,
        api_key_store: storage.api_key_store,
        tenant_store: storage.tenant_store,
        nhi_store: storage.nhi_store,
        session_store: storage.session_store,
        taint_store: storage.taint_store,
        fingerprint_store: storage.fingerprint_store,
        rate_limit_store: storage.rate_limit_store,
        event_bus,
        webhook_manager,
        behavioral_engine,
        rate_limiter,
        threat_feed,
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: storage.storage_backend,
        env: app_env,
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts,
        reasoning,
        #[cfg(feature = "dictum")]
        dictum_overlay,
    });

    let router = create_router(state.clone());

    let addr = format!("{}:{}", state.env.host, state.env.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            process::exit(1);
        }
    };

    tracing::info!(port = state.env.port, db = %db_url, backend = ?state.storage_backend, "IAGA Sentinel listening");

    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("Server error: {e}");
        process::exit(1);
    }

    tracing::info!("IAGA Sentinel shut down gracefully");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl+C, shutting down..."); },
        _ = terminate => { tracing::info!("received SIGTERM, shutting down..."); },
    }
}

// ── inspect ──

async fn cmd_inspect(source: &str, db_url: &str) -> i32 {
    use iaga_sentinel::core::types::*;
    use iaga_sentinel::pipeline::execute_pipeline::execute_pipeline;
    use std::io::Read;

    let raw = if source == "--stdin" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("Failed to read stdin: {e}");
            return 3;
        }
        buf
    } else {
        match std::fs::read_to_string(source) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read file {source}: {e}");
                return 3;
            }
        }
    };

    let payload: InspectRequest = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Invalid JSON input: {e}");
            return 3;
        }
    };

    let storage = match init_storage_bundle(db_url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 3;
        }
    };

    let receipts = try_build_receipt_logger(db_url, None).await;
    let reasoning = try_build_reasoning_engine();
    #[cfg(feature = "dictum")]
    let dictum_overlay: Option<Arc<iaga_sentinel::pipeline::dictum_overlay::DictumOverlay>> = None;

    let state = Arc::new(AppState {
        audit_store: storage.audit_store,
        review_store: storage.review_store,
        policy_store: storage.policy_store,
        api_key_store: storage.api_key_store,
        tenant_store: storage.tenant_store,
        nhi_store: storage.nhi_store,
        session_store: storage.session_store,
        taint_store: storage.taint_store,
        fingerprint_store: storage.fingerprint_store,
        rate_limit_store: storage.rate_limit_store,
        event_bus: EventBus::new(16),
        webhook_manager: Arc::new(WebhookManager::new(Arc::new(
            webhooks::DeadLetterQueue::new(),
        ))),
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: build_threat_feed(),
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: storage.storage_backend,
        env: load_env(),
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts,
        reasoning,
        #[cfg(feature = "dictum")]
        dictum_overlay,
    });

    match execute_pipeline(&payload, &state).await {
        Ok(result) => {
            // Cyberpunk styled output
            let green = "\x1b[38;2;0;255;136m";
            let red = "\x1b[38;2;255;0;85m";
            let cyan = "\x1b[38;2;0;212;255m";
            let yellow = "\x1b[38;2;255;204;0m";
            let dim = "\x1b[38;2;102;102;102m";
            let bold = "\x1b[1m";
            let reset = "\x1b[0m";

            let (decision_color, decision_icon) = match result.decision {
                GovernanceDecision::Allow => (green, "✓ ALLOW"),
                GovernanceDecision::Review => (yellow, "⚠ REVIEW"),
                GovernanceDecision::Block => (red, "✗ BLOCK"),
            };

            eprintln!();
            eprintln!("  {dim}┌─────────────────────────────────────────────┐{reset}");
            eprintln!("  {dim}│{reset} {cyan}IAGA SENTINEL{reset} {dim}// governance result{reset}        {dim}│{reset}");
            eprintln!("  {dim}├─────────────────────────────────────────────┤{reset}");

            // Decision
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");
            eprintln!("  {dim}│{reset}   {bold}{decision_color}{decision_icon}{reset}                            {dim}│{reset}");
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");

            // Risk score bar
            let score = result.risk.score;
            let bar_len = 30;
            let filled = ((score as f64 / 100.0) * bar_len as f64) as usize;
            let bar_color = if score >= 80 {
                red
            } else if score >= 50 {
                yellow
            } else {
                green
            };
            let bar: String = format!(
                "{}{}{}{}",
                bar_color,
                "█".repeat(filled),
                dim,
                "░".repeat(bar_len - filled),
            );
            eprintln!("  {dim}│{reset}   Risk  {bar}{reset} {bold}{score}/100{reset}        {dim}│{reset}");
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");

            // Details
            eprintln!(
                "  {dim}│{reset}   {dim}Agent{reset}     {}",
                result.audit_event.agent_id
            );
            eprintln!(
                "  {dim}│{reset}   {dim}Tool{reset}      {}",
                result.audit_event.tool_name
            );
            eprintln!(
                "  {dim}│{reset}   {dim}Protocol{reset}  {:?}",
                result.protocol
            );
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");

            // Reasons
            if !result.policy_findings.is_empty() {
                eprintln!("  {dim}│{reset}   {cyan}Findings:{reset}");
                for finding in &result.policy_findings {
                    eprintln!("  {dim}│{reset}   {dim}›{reset} {finding}");
                }
            }

            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");
            eprintln!("  {dim}└─────────────────────────────────────────────┘{reset}");
            eprintln!();

            // Still output JSON to stdout for piping
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "traceId": result.trace_id,
                    "decision": result.decision,
                    "reviewStatus": result.review_status,
                    "riskScore": result.risk.score,
                    "reasons": result.risk.reasons,
                    "policyFindings": result.policy_findings,
                    "schemaValidation": result.schema_validation,
                    "secretPlan": result.secret_plan,
                    "protocol": result.protocol,
                }))
                .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
            );

            match result.decision {
                GovernanceDecision::Block => 2,
                GovernanceDecision::Review => 1,
                GovernanceDecision::Allow => 0,
            }
        }
        Err(e) => {
            eprintln!("Pipeline error: {e}");
            3
        }
    }
}

// ── validate ──

fn cmd_validate(config_path: &str) {
    use iaga_sentinel::core::types::SentinelConfig;

    let raw = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read config file: {e}");
            process::exit(1);
        }
    };

    let result: Result<SentinelConfig, String> =
        if config_path.ends_with(".yaml") || config_path.ends_with(".yml") {
            serde_yaml::from_str(&raw).map_err(|e| e.to_string())
        } else {
            serde_json::from_str(&raw).map_err(|e| e.to_string())
        };

    match result {
        Ok(config) => {
            println!("Config is valid!");
            println!("  {} agent profiles", config.profiles.len());
            println!("  {} workspace policies", config.workspaces.len());
            let total_tools: usize = config.workspaces.iter().map(|w| w.tools.len()).sum();
            println!("  {} tool policies", total_tools);
        }
        Err(e) => {
            eprintln!("Invalid config: {e}");
            process::exit(1);
        }
    }
}

// ── plugins ──

fn cmd_plugins_list(dir: Option<&str>, format: &str) {
    let registry = dir
        .map(|plugin_dir| PluginRegistry::new(plugin_dir.into()))
        .unwrap_or_else(PluginRegistry::from_env);
    let snapshot = registry.reload();

    match format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshot)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
            );
        }
        "table" => {
            println!("Plugin directory: {}", snapshot.plugin_dir);
            println!("Loaded plugins: {}", snapshot.loaded_count);

            if snapshot.plugins.is_empty() {
                println!("No plugins loaded.");
            } else {
                println!();
                for plugin in &snapshot.plugins {
                    println!("- {} {} ({})", plugin.name, plugin.version, plugin.path);
                }
            }

            if !snapshot.load_errors.is_empty() {
                println!();
                println!("Load errors:");
                for error in &snapshot.load_errors {
                    println!("- {}: {}", error.path, error.error);
                }
            }
        }
        _ => {
            eprintln!("Unknown format: {format}. Use 'json' or 'table'.");
            process::exit(1);
        }
    }
}

fn cmd_plugins_validate(path: &str, format: &str) {
    let manifest = LoadedPlugin::validate(std::path::Path::new(path)).unwrap_or_else(|e| {
        eprintln!("Invalid plugin: {e}");
        process::exit(1);
    });

    match format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&manifest)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
            );
        }
        "table" => {
            println!("Plugin is valid.");
            println!("  Name:    {}", manifest.name);
            println!("  Version: {}", manifest.version);
            println!("  Path:    {}", manifest.path);
            println!("  Loaded:  {}", manifest.loaded);
        }
        _ => {
            eprintln!("Unknown format: {format}. Use 'json' or 'table'.");
            process::exit(1);
        }
    }
}

// ── dictum type check + wasm compile (1.2) ──

#[cfg(feature = "dictum")]
fn cmd_policy_check(path: &str) -> i32 {
    use iaga_sentinel_dictum::compile_with_types;

    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("policy check: cannot read {path}: {e}");
            return 2;
        }
    };
    match compile_with_types(&src) {
        Ok((program, env)) => {
            println!("CHECK OK  policies={}", program.policies.len());
            for (i, p) in program.policies.iter().enumerate() {
                let ty = env
                    .when_types()
                    .get(i)
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "?".into());
                println!("  policy={:<24} when_type={}", p.name, ty);
            }
            0
        }
        Err(e) => {
            eprintln!("policy check: {e}");
            1
        }
    }
}

#[cfg(feature = "dictum-wasm")]
fn cmd_policy_compile(path: &str, output: Option<&str>) -> i32 {
    use iaga_sentinel_dictum::{compile, compile_to_wasm};

    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("policy compile: cannot read {path}: {e}");
            return 2;
        }
    };
    let program = match compile(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("policy compile: parse/validate failed: {e}");
            return 1;
        }
    };
    let module = match compile_to_wasm(&program) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("policy compile: codegen failed: {e}");
            eprintln!(
                "note: Dictum WASM MVP 1.2 supports literal + boolean / numeric / comparison ops \
only. Path / Call / Membership remain on the tree-walk evaluator. \
See ADR 0014."
            );
            return 1;
        }
    };
    let out_path = output
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{path}.wasm"));
    if let Err(e) = std::fs::write(&out_path, module.bytes()) {
        eprintln!("policy compile: cannot write {out_path}: {e}");
        return 3;
    }
    println!(
        "COMPILED  out={}  bytes={}  policies={}",
        out_path,
        module.bytes().len(),
        module.policy_count()
    );
    0
}

#[cfg(all(feature = "dictum", not(feature = "dictum-wasm")))]
fn cmd_policy_compile(_path: &str, _output: Option<&str>) -> i32 {
    eprintln!(
        "policy compile: requires building with `--features dictum-wasm`. \
The default OSS build ships the tree-walk evaluator only; WASM codegen \
is an opt-in MVP primitive (ADR 0014)."
    );
    2
}

// ── plugin attestation (1.2) ──

#[cfg(feature = "plugin-attestation")]
fn cmd_plugins_verify(path: &str, format: &str) {
    use iaga_sentinel::plugins::verify_plugin;

    let att = match verify_plugin(std::path::Path::new(path)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("verify failed: {e}");
            process::exit(2);
        }
    };

    match format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&att)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
            );
        }
        "table" => {
            println!("plugin verification (offline, ADR 0013)");
            println!("  path:                          {path}");
            println!("  plugin_sha256:                 {}", att.plugin_sha256);
            println!(
                "  sigstore bundle:               {}",
                att.bundle_path
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".into())
            );
            println!(
                "  sbom (cdx.json):               {}",
                att.sbom_path
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".into())
            );
            println!(
                "  bundle well-formed:            {}",
                att.bundle_well_formed
            );
            println!(
                "  payload digest matches:        {}",
                att.payload_digest_match
            );
            println!(
                "  rekor log index:               {}",
                att.rekor_log_index
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "(none)".into())
            );
            if let Some(s) = &att.sbom {
                println!(
                    "  sbom spec_version={} components={}",
                    s.spec_version, s.component_count
                );
            }
            println!(
                "  signature checked (pinned key):{}",
                if att.signature_checked {
                    " yes"
                } else {
                    " no (set IAGA_SENTINEL_PLUGIN_PUBKEY to verify a signature)"
                }
            );
            println!(
                "  signature verified:            {}",
                att.signature_verified
            );
            println!(
                "  attestation level:             {}",
                att.attestation_level()
            );
            if !att.offline_verified() {
                println!();
                println!(
                    "note: this OSS check confirms the bundle is well-formed and (with a \
pinned key via IAGA_SENTINEL_PLUGIN_PUBKEY) that an Ed25519 signature over the \
plugin bytes is valid. It does NOT validate a Fulcio cert chain or a Rekor \
inclusion proof: that managed, keyless identity verification lives in IAGA \
Sentinel Enterprise (ENTERPRISE.md / ADR 0013). A 'digest-only' result means the \
digest matches but no signature was cryptographically verified."
                );
            }
        }
        _ => {
            eprintln!("Unknown format: {format}. Use 'json' or 'table'.");
            process::exit(1);
        }
    }

    // Exit non-zero when a check we actually ran failed, so CI / shell scripts can
    // gate on `iaga plugin verify`. CRYPTO-ATTEST-1: a digest match with no pinned
    // key is "digest-only" and still exits 0 (no regression); a digest MISMATCH,
    // or a pinned-key signature that failed to verify, exits 1.
    let exit_code = if att.bundle_path.is_some()
        && (!att.digest_attested() || (att.signature_checked && !att.signature_verified))
    {
        1
    } else {
        0
    };
    process::exit(exit_code);
}

#[cfg(feature = "plugin-manifest-signing")]
fn resolve_signer_key_path(explicit: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(p) = explicit {
        return Some(std::path::PathBuf::from(p));
    }
    std::env::var("IAGA_SENTINEL_SIGNER_KEY_PATH")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| {
                    let mut p = std::path::PathBuf::from(h);
                    p.push(".iaga-sentinel");
                    p.push("keys");
                    p.push("receipt_signer.ed25519");
                    p
                })
        })
}

#[cfg(feature = "plugin-manifest-signing")]
fn cmd_plugins_sign_manifest(path: &str, key: Option<&str>, name: &str, version: &str) -> i32 {
    use iaga_sentinel::plugins::manifest::sign_manifest;
    use iaga_sentinel_receipts::LocalDiskSigner;

    let key_path = match resolve_signer_key_path(key) {
        Some(p) => p,
        None => {
            eprintln!("iaga plugins sign-manifest: cannot resolve signer key path");
            return 3;
        }
    };
    let signer = match LocalDiskSigner::load_or_create(&key_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga plugins sign-manifest: signer load failed: {e}");
            return 3;
        }
    };
    let created_at = chrono::Utc::now().to_rfc3339();
    match sign_manifest(
        std::path::Path::new(path),
        &signer,
        name,
        version,
        &created_at,
    ) {
        Ok((mpath, spath)) => {
            println!("SIGNED  plugin={path}  signer={}", signer.key_id());
            println!("  manifest:  {}", mpath.display());
            println!("  signature: {}", spath.display());
            println!(
                "  public key (hex, pin this to verify): {}",
                hex::encode(signer.verifying_key().to_bytes())
            );
            0
        }
        Err(e) => {
            eprintln!("iaga plugins sign-manifest: {e}");
            3
        }
    }
}

#[cfg(feature = "plugin-manifest-signing")]
fn cmd_plugins_verify_manifest(path: &str, trusted_keys: &str) -> i32 {
    use ed25519_dalek::VerifyingKey;
    use iaga_sentinel::plugins::manifest::verify_signed_manifest;

    let raw = match std::fs::read_to_string(trusted_keys) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga plugins verify-manifest: cannot read trusted keys {trusted_keys}: {e}");
            return 3;
        }
    };
    let mut keys = Vec::new();
    for tok in raw.split_whitespace() {
        let Ok(bytes) = hex::decode(tok) else {
            continue;
        };
        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            continue;
        };
        if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
            keys.push(vk);
        }
    }
    if keys.is_empty() {
        eprintln!("iaga plugins verify-manifest: no valid 32-byte hex keys in {trusted_keys}");
        return 2;
    }
    let result = verify_signed_manifest(std::path::Path::new(path), &keys);
    let status = if result.verified {
        "VERIFIED"
    } else {
        "UNVERIFIED"
    };
    println!(
        "{status}  plugin={path}  signer={}  reason={}",
        result.signer_key_id.as_deref().unwrap_or("-"),
        result.reason.as_deref().unwrap_or("-")
    );
    if result.verified {
        0
    } else {
        1
    }
}

#[cfg(feature = "plugin-manifest-signing")]
#[allow(clippy::too_many_arguments)]
fn cmd_plugins_attest(
    path: &str,
    slsa_level: u8,
    sign: bool,
    key: Option<&str>,
    out: Option<&str>,
    name: &str,
    version: &str,
) -> i32 {
    use iaga_sentinel::plugins::attest::{build_statement, wrap_dsse, DECLARED_NOTE};
    use iaga_sentinel_receipts::LocalDiskSigner;

    let wasm = std::path::Path::new(path);
    let statement = match build_statement(wasm, name, version, slsa_level) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga plugins attest: cannot read plugin {path}: {e}");
            return 3;
        }
    };

    let (json, default_suffix) = if sign {
        let key_path = match resolve_signer_key_path(key) {
            Some(p) => p,
            None => {
                eprintln!("iaga plugins attest: cannot resolve signer key path");
                return 3;
            }
        };
        let signer = match LocalDiskSigner::load_or_create(&key_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("iaga plugins attest: signer load failed: {e}");
                return 3;
            }
        };
        let envelope = match wrap_dsse(&statement, &signer) {
            Ok(env) => env,
            Err(e) => {
                eprintln!("iaga plugins attest: DSSE encode failed: {e}");
                return 3;
            }
        };
        match serde_json::to_string_pretty(&envelope) {
            Ok(j) => (j, "intoto.dsse.json"),
            Err(e) => {
                eprintln!("iaga plugins attest: serialize failed: {e}");
                return 3;
            }
        }
    } else {
        match serde_json::to_string_pretty(&statement) {
            Ok(j) => (j, "intoto.json"),
            Err(e) => {
                eprintln!("iaga plugins attest: serialize failed: {e}");
                return 3;
            }
        }
    };

    let out_path = match out {
        Some(p) => std::path::PathBuf::from(p),
        None => std::path::PathBuf::from(format!("{path}.{default_suffix}")),
    };
    if let Err(e) = std::fs::write(&out_path, json.as_bytes()) {
        eprintln!(
            "iaga plugins attest: cannot write {}: {e}",
            out_path.display()
        );
        return 3;
    }

    println!("ATTESTED  plugin={path}");
    println!(
        "  subject:   {name}@{version} sha256={}",
        statement.subject[0].digest.sha256
    );
    println!("  predicate: SLSA Provenance v1 (declaredSlsaLevel={slsa_level})");
    if sign {
        println!("  envelope:  DSSE (Ed25519)");
    }
    println!("  output:    {}", out_path.display());
    println!("  NOTE: {DECLARED_NOTE}");
    0
}

// ── migrate ──

async fn cmd_migrate(db_url: &str) {
    match init_storage_bundle(db_url).await {
        Ok(storage) => println!(
            "Migrations completed successfully for {:?}.",
            storage.storage_backend
        ),
        Err(e) => {
            eprintln!("Migration failed: {e}");
            process::exit(1);
        }
    }
}

// ── import ──

async fn cmd_import(config_path: &str, db_url: &str) {
    use iaga_sentinel::core::types::SentinelConfig;

    let raw = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read config file: {e}");
            process::exit(1);
        }
    };

    let config: SentinelConfig = if config_path.ends_with(".yaml") || config_path.ends_with(".yml")
    {
        serde_yaml::from_str(&raw).unwrap_or_else(|e| {
            eprintln!("Invalid YAML: {e}");
            process::exit(1);
        })
    } else {
        serde_json::from_str(&raw).unwrap_or_else(|e| {
            eprintln!("Invalid JSON: {e}");
            process::exit(1);
        })
    };

    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });

    let mut imported = 0;
    for profile in &config.profiles {
        if let Err(e) = storage.policy_store.upsert_profile(profile).await {
            eprintln!("Failed to import profile {}: {e}", profile.agent_id);
        } else {
            imported += 1;
        }
    }
    for workspace in &config.workspaces {
        if let Err(e) = storage.policy_store.upsert_workspace(workspace).await {
            eprintln!("Failed to import workspace {}: {e}", workspace.workspace_id);
        } else {
            imported += 1;
        }
    }

    println!(
        "Imported {} items ({} profiles, {} workspaces)",
        imported,
        config.profiles.len(),
        config.workspaces.len()
    );
}

// ── export ──

async fn cmd_export(db_url: &str, output: Option<&str>) {
    use iaga_sentinel::core::types::SentinelConfig;

    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });

    let profiles = storage
        .policy_store
        .list_profiles()
        .await
        .unwrap_or_default();
    let workspaces = storage
        .policy_store
        .list_workspaces()
        .await
        .unwrap_or_default();

    let config = SentinelConfig {
        profiles,
        workspaces,
        vault: vec![],
    };

    let yaml = serde_yaml::to_string(&config).unwrap_or_else(|e| {
        eprintln!("Failed to serialize: {e}");
        process::exit(1);
    });

    match output {
        Some(path) => {
            std::fs::write(path, &yaml).unwrap_or_else(|e| {
                eprintln!("Failed to write {path}: {e}");
                process::exit(1);
            });
            println!("Exported to {path}");
        }
        None => print!("{yaml}"),
    }
}

// ── gen-key ──

async fn cmd_gen_key(db_url: &str, label: &str, scope: &str) {
    use iaga_sentinel::auth::api_keys::generate_api_key;
    use iaga_sentinel::storage::traits::KeyScope;

    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });

    // Clap's value_parser restricts to admin|agent; from_db maps anything
    // else to Admin defensively.
    let key_scope = KeyScope::from_db(scope);
    let (raw_key, key_hash) = generate_api_key();
    let key_id = uuid::Uuid::new_v4().to_string();

    storage
        .api_key_store
        .store_key_scoped(&key_id, &key_hash, label, &raw_key, key_scope)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to store key: {e}");
            process::exit(1);
        });

    println!("API Key created:");
    println!("  ID:    {key_id}");
    println!("  Key:   {raw_key}");
    println!("  Label: {label}");
    println!("  Scope: {}", key_scope.as_str());
    println!();
    println!("Save this key now, it cannot be retrieved again.");
}

// ── audit ──

#[cfg(feature = "cost-control")]
async fn cmd_cost(db_url: &str, view: &str, from: Option<&str>, to: Option<&str>, limit: u32) {
    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    let store = &storage.audit_store;

    let value: serde_json::Value = match view {
        "summary" => {
            let s = store.cost_summary(from, to).await.unwrap_or_else(|e| {
                eprintln!("cost_summary failed: {e}");
                process::exit(1);
            });
            serde_json::to_value(s).unwrap_or_default()
        }
        "by-model" => serde_json::to_value(
            store
                .cost_by_model(from, to, limit)
                .await
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
        "by-agent" => serde_json::to_value(
            store
                .cost_by_agent(from, to, limit)
                .await
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
        "by-tool" => serde_json::to_value(
            store
                .cost_by_tool(from, to, limit)
                .await
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
        "budget" => serde_json::json!({
            "sessionLimitUsd": iaga_sentinel::pipeline::cost::session_budget_usd(),
        }),
        other => {
            eprintln!(
                "unknown view '{other}' (use: summary | by-model | by-agent | by-tool | budget)"
            );
            process::exit(2);
        }
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
    );
}

async fn cmd_audit(db_url: &str, limit: u32, format: &str) {
    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });

    let events = storage.audit_store.list(limit).await.unwrap_or_else(|e| {
        eprintln!("Failed to fetch audit events: {e}");
        process::exit(1);
    });

    match format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&events)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
            );
        }
        "table" => {
            let green = "\x1b[38;2;0;255;136m";
            let red = "\x1b[38;2;255;0;85m";
            let cyan = "\x1b[38;2;0;212;255m";
            let yellow = "\x1b[38;2;255;204;0m";
            let dim = "\x1b[38;2;102;102;102m";
            let bold = "\x1b[1m";
            let reset = "\x1b[0m";

            eprintln!();
            eprintln!("  {dim}┌─────────────────────────────────────────────┐{reset}");
            eprintln!("  {dim}│{reset} {cyan}IAGA SENTINEL{reset} {dim}// audit trail{reset}               {dim}│{reset}");
            eprintln!("  {dim}└─────────────────────────────────────────────┘{reset}");
            eprintln!();

            println!(
                "  {cyan}{bold}{:<36} {:<16} {:<20} {:<10} {:<6} TIMESTAMP{reset}",
                "EVENT_ID", "AGENT", "TOOL", "DECISION", "RISK"
            );
            println!("  {dim}{}{reset}", "─".repeat(110));
            for e in &events {
                use iaga_sentinel::core::types::GovernanceDecision;
                let decision_color = match e.decision {
                    GovernanceDecision::Allow => green,
                    GovernanceDecision::Review => yellow,
                    GovernanceDecision::Block => red,
                };
                let risk_color = if e.risk_score >= 80 {
                    red
                } else if e.risk_score >= 50 {
                    yellow
                } else {
                    green
                };
                println!(
                    "  {:<36} {:<16} {:<20} {decision_color}{:<10?}{reset} {risk_color}{:<6}{reset} {dim}{}{reset}",
                    e.event_id, e.agent_id, e.tool_name, e.decision, e.risk_score, e.timestamp
                );
            }
            eprintln!();
            eprintln!("  {dim}{} events{reset}", events.len());
            eprintln!();
        }
        _ => {
            eprintln!("Unknown format: {format}. Use 'json' or 'table'.");
            process::exit(1);
        }
    }
}

// ── helpers ──

/// Build the runtime threat feed: the built-in indicators plus any operator
/// `threat-intel.toml` named by `IAGA_SENTINEL_THREAT_FEED`. The TOML file is the
/// OSS *format*; the curated, signed Enterprise feed is a separate product
/// (ADR 0010). A missing/malformed file is logged and skipped — the built-in
/// baseline still applies, so a bad config never silently disarms the feed.
fn build_threat_feed() -> Arc<ThreatFeed> {
    let feed = ThreatFeed::with_builtin_indicators();
    if let Ok(path) = std::env::var("IAGA_SENTINEL_THREAT_FEED") {
        let path = path.trim();
        if !path.is_empty() {
            match std::fs::read_to_string(path) {
                Ok(text) => match ThreatFeed::indicators_from_toml(&text) {
                    Ok(extra) => {
                        let count = extra.len();
                        for indicator in extra {
                            feed.add_indicator(indicator);
                        }
                        tracing::info!(path, count, "Loaded threat-intel.toml indicators");
                    }
                    Err(e) => tracing::warn!(
                        path,
                        error = %e,
                        "Invalid threat-intel.toml; using built-in indicators only"
                    ),
                },
                Err(e) => tracing::warn!(
                    path,
                    error = %e,
                    "Cannot read IAGA_SENTINEL_THREAT_FEED; using built-in indicators only"
                ),
            }
        }
    }
    Arc::new(feed)
}

/// Register an operator-supplied admin key from `IAGA_SENTINEL_BOOTSTRAP_API_KEY`.
///
/// Without this, a fresh database plus `openMode: false` — which is what every
/// deployment artifact in this repo configures — leaves every route answering
/// 401 until someone execs into the container and runs `iaga gen-key`, and the
/// generated key is unknowable to clients configured ahead of time.
///
/// Idempotent: if the key already verifies, nothing is written. Concurrent
/// replicas racing on a shared Postgres each insert their own row (the UNIQUE
/// index is on `key_hash`, and Argon2 salts per call, so identical keys never
/// collide). That is benign — every row grants the same key the same scope.
async fn bootstrap_api_key_from_env(store: &Arc<dyn iaga_sentinel::storage::traits::ApiKeyStore>) {
    use iaga_sentinel::auth::api_keys::{hash_key, validate_bootstrap_key, BOOTSTRAP_ENV};
    use iaga_sentinel::storage::traits::KeyScope;

    let raw = match std::env::var(BOOTSTRAP_ENV) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Err(why) = validate_bootstrap_key(&raw) {
        // Fail loudly: the operator asked for authentication and would
        // otherwise get a server that silently ignored the request.
        eprintln!("{BOOTSTRAP_ENV} is set but invalid: {why}.");
        process::exit(2);
    }

    match store.verify_raw_key_scoped(&raw).await {
        Ok(Some(_)) => {
            tracing::info!("bootstrap API key already registered; nothing to do");
            return;
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Failed to check the existing API keys for {BOOTSTRAP_ENV}: {e}");
            process::exit(2);
        }
    }

    let key_id = uuid::Uuid::new_v4().to_string();
    let key_hash = hash_key(&raw);
    match store
        .store_key_scoped(&key_id, &key_hash, "bootstrap", &raw, KeyScope::Admin)
        .await
    {
        // The key itself is never logged: it is a live admin credential.
        Ok(()) => tracing::info!(key_id = %key_id, "registered admin API key from {BOOTSTRAP_ENV}"),
        Err(e) => {
            eprintln!("Failed to register the API key from {BOOTSTRAP_ENV}: {e}");
            process::exit(2);
        }
    }
}

/// Refuse to serve when the operator asked for fail-closed receipts but no
/// receipt logger could be built (no signer key, store open failure, or the
/// `receipts` feature compiled out). Serving anyway would make the *worst*
/// misconfiguration the *most* permissive one: with no logger every action is
/// allowed unevidenced, while a merely broken logger blocks. Called from the
/// long-running surfaces only — `serve`, `proxy`, `mcp-server`, `run` — not
/// from the one-shot developer commands.
fn require_receipts_or_exit(
    receipts: &Option<Arc<dyn iaga_sentinel::pipeline::receipts::ReceiptLogger>>,
) {
    if receipts.is_none() && iaga_sentinel::pipeline::receipts::fail_closed_enabled() {
        eprintln!(
            "IAGA_SENTINEL_RECEIPT_FAIL_CLOSED is set but no receipt logger could be built.\n\
             Refusing to start: every verdict would be returned with no signed evidence behind it.\n\
             Check the signer key path and the receipt store, or unset the variable."
        );
        process::exit(2);
    }
}

async fn seed_demo_data(policy_store: &Arc<dyn PolicyStore>) {
    use iaga_sentinel::demo::scenarios::{demo_profiles, demo_workspace_policies};

    let profiles = policy_store.list_profiles().await.unwrap_or_default();
    if !profiles.is_empty() {
        return;
    }

    tracing::info!("Seeding demo data into database...");
    for profile in demo_profiles() {
        if let Err(e) = policy_store.upsert_profile(&profile).await {
            tracing::warn!(agent_id = %profile.agent_id, error = %e, "Failed to seed demo profile");
        }
    }
    for workspace in demo_workspace_policies() {
        if let Err(e) = policy_store.upsert_workspace(&workspace).await {
            tracing::warn!(workspace_id = %workspace.workspace_id, error = %e, "Failed to seed demo workspace");
        }
    }
    tracing::info!("Demo data seeded");
}

async fn cmd_proxy(db_url: &str, agent_id: &str, command: &str, args: Vec<String>) {
    use iaga_sentinel::mcp_proxy::proxy_server::{run_mcp_proxy, McpProxyConfig};

    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    seed_demo_data(&storage.policy_store).await;

    let event_bus = EventBus::new(256);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(
        webhooks::DeadLetterQueue::new(),
    )));

    let receipts = try_build_receipt_logger(db_url, None).await;
    require_receipts_or_exit(&receipts);
    let reasoning = try_build_reasoning_engine();
    #[cfg(feature = "dictum")]
    let dictum_overlay: Option<Arc<iaga_sentinel::pipeline::dictum_overlay::DictumOverlay>> = None;

    let state = Arc::new(AppState {
        audit_store: storage.audit_store,
        review_store: storage.review_store,
        policy_store: storage.policy_store,
        api_key_store: storage.api_key_store,
        tenant_store: storage.tenant_store,
        nhi_store: storage.nhi_store,
        session_store: storage.session_store,
        taint_store: storage.taint_store,
        fingerprint_store: storage.fingerprint_store,
        rate_limit_store: storage.rate_limit_store,
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: build_threat_feed(),
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: storage.storage_backend,
        env: load_env(),
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts,
        reasoning,
        #[cfg(feature = "dictum")]
        dictum_overlay,
    });

    let config = McpProxyConfig {
        agent_id: agent_id.to_string(),
        downstream_command: command.to_string(),
        downstream_args: args,
        downstream_env: std::collections::HashMap::new(),
    };

    if let Err(e) = run_mcp_proxy(config, state).await {
        eprintln!("MCP proxy error: {e}");
        process::exit(1);
    }
}

async fn cmd_mcp_server(db_url: &str, seed_demo: bool) {
    use iaga_sentinel::mcp_server::server::run_mcp_server;

    let storage = init_storage_bundle(db_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });

    if seed_demo {
        seed_demo_data(&storage.policy_store).await;
    }

    let event_bus = EventBus::new(256);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(
        webhooks::DeadLetterQueue::new(),
    )));

    let receipts = try_build_receipt_logger(db_url, None).await;
    require_receipts_or_exit(&receipts);
    let reasoning = try_build_reasoning_engine();
    #[cfg(feature = "dictum")]
    let dictum_overlay: Option<Arc<iaga_sentinel::pipeline::dictum_overlay::DictumOverlay>> = None;

    let state = Arc::new(AppState {
        audit_store: storage.audit_store,
        review_store: storage.review_store,
        policy_store: storage.policy_store,
        api_key_store: storage.api_key_store,
        tenant_store: storage.tenant_store,
        nhi_store: storage.nhi_store,
        session_store: storage.session_store,
        taint_store: storage.taint_store,
        fingerprint_store: storage.fingerprint_store,
        rate_limit_store: storage.rate_limit_store,
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: build_threat_feed(),
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: storage.storage_backend,
        env: load_env(),
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts,
        reasoning,
        #[cfg(feature = "dictum")]
        dictum_overlay,
    });

    if let Err(e) = run_mcp_server(state).await {
        eprintln!("MCP server error: {e}");
        process::exit(1);
    }
}

async fn cmd_mcp_doctor(
    db_url: &str,
    agent_id: &str,
    command: &str,
    args: Vec<String>,
    probe_tool: Option<String>,
    format: &str,
) -> i32 {
    use iaga_sentinel::mcp_doctor::{run_doctor, DoctorConfig};

    let storage = match init_storage_bundle(db_url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    // Seed demo policies so the governance encapsulability check has rules to
    // evaluate against out of the box.
    seed_demo_data(&storage.policy_store).await;

    let event_bus = EventBus::new(256);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(
        webhooks::DeadLetterQueue::new(),
    )));

    let receipts = try_build_receipt_logger(db_url, None).await;
    let reasoning = try_build_reasoning_engine();
    #[cfg(feature = "dictum")]
    let dictum_overlay: Option<Arc<iaga_sentinel::pipeline::dictum_overlay::DictumOverlay>> = None;

    let state = Arc::new(AppState {
        audit_store: storage.audit_store,
        review_store: storage.review_store,
        policy_store: storage.policy_store,
        api_key_store: storage.api_key_store,
        tenant_store: storage.tenant_store,
        nhi_store: storage.nhi_store,
        session_store: storage.session_store,
        taint_store: storage.taint_store,
        fingerprint_store: storage.fingerprint_store,
        rate_limit_store: storage.rate_limit_store,
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: build_threat_feed(),
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: storage.storage_backend,
        env: load_env(),
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts,
        reasoning,
        #[cfg(feature = "dictum")]
        dictum_overlay,
    });

    let config = DoctorConfig {
        agent_id: agent_id.to_string(),
        command: command.to_string(),
        args,
        probe_tool,
    };

    let report = run_doctor(&state, config).await;

    if format.eq_ignore_ascii_case("json") {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("failed to serialize doctor report: {e}");
                return 1;
            }
        }
    } else {
        print!("{}", report.render_table());
    }

    report.exit_code()
}

async fn auto_import_config(policy_store: &Arc<dyn PolicyStore>) {
    for name in &[
        "iaga-sentinel.yaml",
        "iaga-sentinel.yml",
        "iaga-sentinel.json",
    ] {
        if std::path::Path::new(name).exists() {
            tracing::info!(file = name, "Found config file, auto-importing...");
            // A config file that is PRESENT but unusable is an operator error,
            // not an absence: warning and carrying on starts a server with zero
            // profiles and zero workspaces that looks configured and governs
            // nothing. The Helm chart shipped exactly that (an empty default
            // mounted over the image's policy), so this is fatal from 1.9.
            // A missing file stays non-fatal — that is a legitimate setup.
            let raw = match std::fs::read_to_string(name) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Cannot read config file {name}: {e}");
                    process::exit(2);
                }
            };

            let config: iaga_sentinel::core::types::SentinelConfig =
                if name.ends_with(".yaml") || name.ends_with(".yml") {
                    match serde_yaml::from_str(&raw) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!(
                                "Config file {name} is present but could not be parsed: {e}\n\
                                 It must define `profiles` and `workspaces`. Refusing to start \
                                 with no policy loaded."
                            );
                            process::exit(2);
                        }
                    }
                } else {
                    match serde_json::from_str(&raw) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!(
                                "Config file {name} is present but could not be parsed: {e}\n\
                                 It must define `profiles` and `workspaces`. Refusing to start \
                                 with no policy loaded."
                            );
                            process::exit(2);
                        }
                    }
                };

            for p in &config.profiles {
                if let Err(e) = policy_store.upsert_profile(p).await {
                    tracing::warn!(agent_id = %p.agent_id, error = %e, "Failed to import profile from config");
                }
            }
            for w in &config.workspaces {
                if let Err(e) = policy_store.upsert_workspace(w).await {
                    tracing::warn!(workspace_id = %w.workspace_id, error = %e, "Failed to import workspace from config");
                }
            }
            tracing::info!(
                profiles = config.profiles.len(),
                workspaces = config.workspaces.len(),
                "Config imported"
            );
            break;
        }
    }
}

#[cfg(feature = "dictum")]
fn cmd_policy_test(path: &str, context_path: Option<&str>) -> i32 {
    use iaga_sentinel_dictum::{compile, evaluate_program, Context, EvalBudget};

    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga policy test: cannot read {}: {}", path, e);
            return 2;
        }
    };
    let program = match compile(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    println!(
        "OK  parsed {} polic{}  from {}",
        program.policies.len(),
        if program.policies.len() == 1 {
            "y"
        } else {
            "ies"
        },
        path
    );
    for p in &program.policies {
        println!("  - {} \u{2192} {:?}", p.name, p.action.verdict);
    }

    let Some(ctx_path) = context_path else {
        return 0;
    };
    let ctx_raw = match std::fs::read_to_string(ctx_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga policy test: cannot read context {}: {}", ctx_path, e);
            return 2;
        }
    };
    let ctx_json: serde_json::Value = match serde_json::from_str(&ctx_raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("iaga policy test: context is not valid JSON: {}", e);
            return 2;
        }
    };
    let ctx = Context::from_value(ctx_json);
    let mut budget = EvalBudget::default();
    match evaluate_program(&program, &ctx, &mut budget) {
        Ok(Some(fired)) => {
            println!(
                "FIRE  policy={}  verdict={:?}  reason={:?}",
                fired.policy_name, fired.verdict, fired.reason
            );
            if let Some(ev) = fired.evidence {
                println!("       evidence={}", ev);
            }
            0
        }
        Ok(None) => {
            println!("MISS  no policy fired");
            0
        }
        Err(e) => {
            eprintln!("EVAL ERR  {}", e);
            1
        }
    }
}

#[cfg(feature = "reasoning")]
fn cmd_reasoning_info() {
    let Some(eng) = try_build_reasoning_engine() else {
        println!("no reasoning engine configured");
        return;
    };
    println!("engine: {}", eng.engine_name());
    let digests = eng.model_digests();
    if digests.is_empty() {
        println!("models: 0 (engine active, no models loaded)");
        if cfg!(feature = "ml") {
            println!(
                "  hint: set IAGA_SENTINEL_REASONING_MODELS=name1:/path/to/a.onnx,name2:/path/to/b.onnx"
            );
        } else {
            println!("  hint: rebuild with --features ml to load ONNX models");
        }
        return;
    }
    println!("models: {}", digests.len());
    for (name, sha) in digests {
        println!("  - {:<24} sha256={}", name, sha);
    }
}

#[cfg(feature = "kernel")]
fn cmd_kernel_status() {
    use iaga_sentinel_kernel::{EnforcementKernel, UserspaceKernel};
    let k = UserspaceKernel::allow_all();
    println!("backend: {}", k.backend_name());
    println!(
        "authoritative: {}",
        if k.is_authoritative() {
            "yes"
        } else {
            "no — userspace process-boundary enforcement (kernel eBPF/LSM is Enterprise)"
        }
    );
    // What the userspace backend actually confines a governed child with.
    // Platform-aware so the line never overclaims (e.g. no rlimits on Windows).
    #[cfg(unix)]
    let containment = if cfg!(target_os = "linux") {
        "env-scrubbed, no-core-dumps, no-new-privs, reaped"
    } else {
        "env-scrubbed, no-core-dumps, reaped"
    };
    #[cfg(not(unix))]
    let containment = "env-scrubbed, reaped";
    println!("containment: {containment}");
    if cfg!(feature = "linux-bpf") && cfg!(target_os = "linux") {
        println!("linux-bpf: scaffold compiled (authoritative loader is Enterprise, ADR 0010)");
    } else {
        println!("linux-bpf: not active on this build");
    }
}

#[cfg(feature = "kernel")]
async fn cmd_kernel_run(db_url: &str, agent_id: &str, cwd: Option<&str>, cmd: &[String]) -> i32 {
    use iaga_sentinel::core::types::{
        ActionDetail, ActionType, GovernanceDecision, InspectRequest,
    };
    use iaga_sentinel::pipeline::execute_pipeline::execute_pipeline;
    use iaga_sentinel_kernel::{
        EnforcementKernel, KernelDecision, PolicyCheck, ProcessSpec, UserspaceKernel,
    };

    if cmd.is_empty() {
        eprintln!("iaga run: missing command after `--`");
        return 2;
    }
    let (program, args) = (cmd[0].clone(), cmd[1..].to_vec());
    let spec = ProcessSpec {
        agent_id: agent_id.to_string(),
        program: program.clone(),
        args: args.clone(),
        working_dir: cwd.map(|s| s.to_string()),
        env: Vec::new(),
    };

    // M5: build a real AppState so the policy callback can run the
    // governance pipeline. Receipts produced by the pipeline (M2) are
    // signed and chained per launch automatically.
    let storage = match init_storage_bundle(db_url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[iaga run] storage init failed: {e}");
            return 3;
        }
    };
    // First-run convenience: if no profiles exist yet, seed the demo set
    // so `iaga run` works out of the box without requiring a separate
    // `iaga migrate` + import step.
    seed_demo_data(&storage.policy_store).await;
    let receipts = try_build_receipt_logger(db_url, None).await;
    require_receipts_or_exit(&receipts);
    let reasoning = try_build_reasoning_engine();
    #[cfg(feature = "dictum")]
    let dictum_overlay: Option<Arc<iaga_sentinel::pipeline::dictum_overlay::DictumOverlay>> = None;
    let event_bus = EventBus::new(16);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(
        webhooks::DeadLetterQueue::new(),
    )));
    let state = Arc::new(AppState {
        audit_store: storage.audit_store,
        review_store: storage.review_store,
        policy_store: storage.policy_store,
        api_key_store: storage.api_key_store,
        tenant_store: storage.tenant_store,
        nhi_store: storage.nhi_store,
        session_store: storage.session_store,
        taint_store: storage.taint_store,
        fingerprint_store: storage.fingerprint_store,
        rate_limit_store: storage.rate_limit_store,
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: build_threat_feed(),
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: storage.storage_backend,
        env: load_env(),
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts,
        reasoning,
        #[cfg(feature = "dictum")]
        dictum_overlay,
    });

    // Policy callback: synthesize an InspectRequest from the ProcessSpec
    // and run it through the governance pipeline. Pipeline verdict maps
    // 1:1 onto KernelDecision; the pipeline also writes a signed receipt
    // for this launch as a side effect (M2 dual-write).
    let state_for_cb = state.clone();
    let policy: PolicyCheck = Arc::new(move |spec: &ProcessSpec| {
        let state = state_for_cb.clone();
        let mut payload = std::collections::HashMap::new();
        payload.insert(
            "program".to_string(),
            serde_json::Value::String(spec.program.clone()),
        );
        payload.insert(
            "args".to_string(),
            serde_json::Value::Array(
                spec.args
                    .iter()
                    .map(|a| serde_json::Value::String(a.clone()))
                    .collect(),
            ),
        );
        if let Some(cwd) = &spec.working_dir {
            payload.insert("cwd".to_string(), serde_json::Value::String(cwd.clone()));
        }
        let request = InspectRequest {
            agent_id: spec.agent_id.clone(),
            tenant_id: None,
            workspace_id: None,
            framework: "iaga-sentinel-kernel".into(),
            protocol: None,
            action: ActionDetail {
                action_type: ActionType::Shell,
                tool_name: spec.program.clone(),
                payload,
            },
            requested_secrets: None,
            metadata: None,
            usage: None,
        };
        Box::pin(async move {
            match execute_pipeline(&request, &state).await {
                Ok(result) => match result.decision {
                    GovernanceDecision::Allow => KernelDecision::Allow,
                    GovernanceDecision::Review => KernelDecision::Review,
                    GovernanceDecision::Block => KernelDecision::Block,
                },
                Err(e) => {
                    tracing::error!(error = %e, "iaga run: pipeline error; failing closed");
                    KernelDecision::Block
                }
            }
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
    });

    let kernel = UserspaceKernel::new(policy);
    println!(
        "[iaga run] backend={} agent={} program={} args={:?}",
        kernel.backend_name(),
        spec.agent_id,
        spec.program,
        spec.args
    );
    match kernel.launch(&spec).await {
        Ok(out) => {
            if let Some(reason) = &out.reason {
                println!("[iaga run] reason: {}", reason);
            }
            if let Some(pid) = out.pid {
                println!("[iaga run] pid: {}", pid);
            }
            println!("[iaga run] decision: {:?}", out.decision);
            out.exit_code.unwrap_or(0)
        }
        Err(e) => {
            eprintln!("[iaga run] error: {}", e);
            3
        }
    }
}

#[cfg(feature = "receipts")]
async fn cmd_replay(
    db_url: &str,
    run_id: Option<&str>,
    verify_only: bool,
    list: bool,
    limit: u32,
    re_execute: bool,
    export: Option<&str>,
) -> i32 {
    use iaga_sentinel_receipts::{
        ChainExport, ChainStatus, ReceiptSigner, ReceiptStore, SqliteReceiptStore,
    };

    if !db_url.starts_with("sqlite:") {
        eprintln!("iaga replay: only sqlite:// URLs are supported in 1.0-alpha.1");
        return 2;
    }

    let key_path = match std::env::var("IAGA_SENTINEL_SIGNER_KEY_PATH")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| {
                    let mut p = std::path::PathBuf::from(h);
                    p.push(".iaga-sentinel");
                    p.push("keys");
                    p.push("receipt_signer.ed25519");
                    p
                })
        }) {
        Some(p) => p,
        None => {
            eprintln!("iaga replay: cannot resolve signer key path");
            return 3;
        }
    };

    let signer = match ReceiptSigner::load_or_create(&key_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga replay: signer load failed: {e}");
            return 3;
        }
    };

    let store = match SqliteReceiptStore::new(db_url, signer.verifying_key()).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga replay: store open failed: {e}");
            return 3;
        }
    };

    if list {
        match store.list_runs(limit).await {
            Ok(runs) => {
                if runs.is_empty() {
                    println!("no runs recorded");
                    return 0;
                }
                println!(
                    "{:<36} {:>6} {:>8} {:<25} {:<25}",
                    "run_id", "count", "verdict", "first", "last"
                );
                for r in runs {
                    println!(
                        "{:<36} {:>6} {:>8?} {:<25} {:<25}",
                        r.run_id,
                        r.receipt_count,
                        r.terminal_verdict,
                        r.first_timestamp,
                        r.last_timestamp
                    );
                }
                return 0;
            }
            Err(e) => {
                eprintln!("iaga replay --list: {e}");
                return 3;
            }
        }
    }

    let rid: String = match run_id {
        None => {
            eprintln!("iaga replay: pass <run_id> or use --list");
            return 2;
        }
        Some(arg) => {
            // PIP-RUNID-COLLISION: run_ids are now `agent_id:session_id`. Accept
            // an exact run_id, or resolve a bare session_id when it maps to
            // exactly one run, so `iaga replay <sessionId>` keeps working.
            let exact = store
                .get_run(arg)
                .await
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            if exact {
                arg.to_string()
            } else if let Ok(runs) = store.list_runs(10_000).await {
                let mut hits = runs
                    .into_iter()
                    .map(|r| r.run_id)
                    .filter(|id| id.rsplit_once(':').map(|(_, s)| s) == Some(arg));
                match (hits.next(), hits.next()) {
                    (Some(only), None) => only,
                    (Some(_), Some(_)) => {
                        eprintln!(
                            "iaga replay: '{arg}' matches multiple runs; \
                             pass the full agent_id:session_id"
                        );
                        return 2;
                    }
                    _ => arg.to_string(),
                }
            } else {
                arg.to_string()
            }
        }
    };
    let rid = rid.as_str();

    if let Some(out_path) = export {
        let chain = match store.get_run(rid).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("iaga replay --export: get_run: {e}");
                return 3;
            }
        };
        let count = chain.len();
        let doc = ChainExport {
            run_id: rid.to_string(),
            signer_key_id: signer.key_id().to_string(),
            signer_verifying_key: hex::encode(signer.verifying_key().to_bytes()),
            receipts: chain,
        };
        let json = match serde_json::to_string_pretty(&doc) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("iaga replay --export: serialize: {e}");
                return 3;
            }
        };
        if let Err(e) = std::fs::write(out_path, json) {
            eprintln!("iaga replay --export: write {out_path}: {e}");
            return 3;
        }
        println!(
            "EXPORTED  run_id={}  receipts={}  signer={}  file={}",
            rid,
            count,
            signer.key_id(),
            out_path
        );
        return 0;
    }

    match store.verify_chain(rid).await {
        Ok(ChainStatus::Valid { receipt_count }) => {
            println!(
                "CHAIN OK  run_id={}  receipts={}  signer={}",
                rid,
                receipt_count,
                signer.key_id()
            );
        }
        Ok(ChainStatus::Broken { seq, reason }) => {
            eprintln!(
                "CHAIN BROKEN  run_id={}  seq={}  reason={}",
                rid, seq, reason
            );
            return 1;
        }
        Ok(ChainStatus::Empty) => {
            eprintln!("CHAIN EMPTY  run_id={}", rid);
            return 1;
        }
        Err(e) => {
            eprintln!("iaga replay: verify_chain error: {e}");
            return 3;
        }
    }

    if verify_only {
        return 0;
    }

    // Drift replay: for M2 we do a minimal identity replay, no pipeline
    // re-execution, we just print the stored verdict chain. Full drift
    // replay against the current pipeline is M5.
    let chain = match store.get_run(rid).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("iaga replay: get_run: {e}");
            return 3;
        }
    };

    if re_execute {
        // 1.2: surface the optional capture data and report whether
        // the receipt has enough material for a hypothetical
        // re-execution. Full pipeline re-execution wiring is on the
        // 1.3 roadmap; this MVP makes the capture data inspectable
        // and confirms 1.1 receipts (no capture) are still chain-valid.
        let mut with_capture = 0u64;
        let mut without_capture = 0u64;
        println!("RE-EXECUTE  run_id={}  receipts={}", rid, chain.len());
        for r in &chain {
            let capture_present = r.body.pipeline_inputs_capture.is_some();
            let dictum_trace_present = r.body.apl_eval_trace.is_some();
            let ml_inputs_present = r.body.ml_inference_inputs.is_some();
            let marker = if capture_present { "✓" } else { "·" };
            println!(
                "  seq={:<4} verdict={:<8?} capture={} dictum_trace={} ml_inputs={} reasons={:?}",
                r.body.seq,
                r.body.verdict,
                marker,
                if dictum_trace_present { "✓" } else { "·" },
                if ml_inputs_present { "✓" } else { "·" },
                r.body.reasons,
            );
            if capture_present {
                with_capture += 1;
            } else {
                without_capture += 1;
            }
        }
        println!(
            "summary: {with_capture}/{total} with capture, {without_capture}/{total} without (1.1 / capture-disabled)",
            total = chain.len()
        );
        if without_capture > 0 {
            println!(
                "note: receipts without capture were produced with IAGA_SENTINEL_RECEIPT_CAPTURE unset; \
re-executable evidence is the union of stored verdict/reasons only."
            );
        }
        return 0;
    }

    for r in chain {
        println!(
            "  seq={:<4} verdict={:<8?} risk={:<3} reasons={:?}",
            r.body.seq, r.body.verdict, r.body.risk_score, r.body.reasons
        );
    }
    0
}
