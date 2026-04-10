use anyhow::{Context, Result, bail};
use common::ProxySrcKey;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

mod db;
mod loader;
mod maps;
mod resolver;

/// Parse a 64-character hex string into a 32-byte `ProxySrcKey`.
///
/// Bytes 0-15 → PRINCE key, bytes 16-31 → SipHash-2-4 key.
/// Rejects all-zero keys (not populated / invalid).
fn parse_proxy_key_hex(hex: &str) -> Result<ProxySrcKey> {
    let hex = hex.trim();
    if hex.len() != 64 {
        bail!(
            "PROXY_ADDR_KEY_HEX must be exactly 64 hex characters (32 bytes), got {}",
            hex.len()
        );
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at position {}", i * 2))?;
    }
    let mut prince_key = [0u8; 16];
    let mut siphash_key = [0u8; 16];
    prince_key.copy_from_slice(&bytes[0..16]);
    siphash_key.copy_from_slice(&bytes[16..32]);

    let key = ProxySrcKey {
        prince_key,
        siphash_key,
    };
    if key.is_zero() {
        bail!("PROXY_ADDR_KEY_HEX must not be all zeros");
    }
    Ok(key)
}

/// Compute a short fingerprint of the key for logging (first 8 hex chars of
/// a simple hash). Does NOT leak the key itself.
fn key_fingerprint(key: &ProxySrcKey) -> String {
    // Simple non-cryptographic fingerprint: XOR-fold all 32 bytes into 4 bytes.
    let mut fp = [0u8; 4];
    for i in 0..16 {
        fp[i % 4] ^= key.prince_key[i];
        fp[i % 4] ^= key.siphash_key[i];
    }
    format!("{:02x}{:02x}{:02x}{:02x}", fp[0], fp[1], fp[2], fp[3])
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to set tracing subscriber")?;

    // Read environment variables
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable not set")?;
    let interface_name =
        std::env::var("INTERFACE_NAME").context("INTERFACE_NAME environment variable not set")?;
    let wan_interface =
        std::env::var("WAN_INTERFACE").context("WAN_INTERFACE environment variable not set")?;

    // Parse proxy-source obfuscation key (required).
    let active_key = {
        let hex = std::env::var("PROXY_ADDR_KEY_HEX")
            .context("PROXY_ADDR_KEY_HEX environment variable not set (generate with: openssl rand -hex 32)")?;
        // Remove env var from process environment to limit exposure window.
        // SAFETY: we are in single-threaded init (before spawning Tokio tasks),
        // and no other thread is reading or writing environment variables.
        unsafe { std::env::remove_var("PROXY_ADDR_KEY_HEX") };
        parse_proxy_key_hex(&hex).context("invalid PROXY_ADDR_KEY_HEX")?
    };
    info!(
        "Loaded active proxy-source key (fingerprint: {})",
        key_fingerprint(&active_key)
    );

    // Parse optional previous key for rotation grace window.
    let prev_key = match std::env::var("PROXY_ADDR_PREV_KEY_HEX") {
        Ok(hex) => {
            // SAFETY: same as above — single-threaded init context.
            unsafe { std::env::remove_var("PROXY_ADDR_PREV_KEY_HEX") };
            let key = parse_proxy_key_hex(&hex).context("invalid PROXY_ADDR_PREV_KEY_HEX")?;
            info!(
                "Loaded previous proxy-source key (fingerprint: {})",
                key_fingerprint(&key)
            );
            Some(key)
        }
        Err(_) => None,
    };

    info!("Starting daemon");
    info!("Tunnel interface: {interface_name}");
    info!("WAN interface: {wan_interface}");

    #[cfg(feature = "dev-mode")]
    info!("Running in DEV MODE - double-NAT enabled for testing");

    // Wait indefinitely for the tunnel interface (e.g. xfrm0) to appear.
    // xfrm0 is created by prototype-xfrm0.service; on a fresh server it exists
    // before this service starts (systemd ordering). If it ever disappears and
    // is recreated, BindsTo= in the service unit restarts the daemon, which
    // will re-enter this loop and re-attach once the interface reappears.
    // Exits early (Err) only on SIGINT / SIGTERM so the process shuts down
    // cleanly instead of looping forever when asked to stop.
    info!("Waiting for tunnel interface {interface_name}...");
    loader::wait_for_interface(&interface_name).await?;

    // Load eBPF programs and attach to interfaces
    info!("Loading eBPF programs...");
    let mut bpf = loader::load_and_attach(
        &interface_name,
        &wan_interface,
        &active_key,
        prev_key.as_ref(),
    )?;

    // Connect to database
    info!("Connecting to database...");
    let db_pool = db::create_pool(&database_url).await?;

    // Bulk-load all existing domain mappings into BPF maps
    info!("Bulk-loading existing domain mappings into BPF maps...");
    let count = maps::bulk_load_from_db(&mut bpf, &db_pool).await?;
    info!("Loaded {count} domain mappings into BPF maps");

    // Spawn LISTEN/NOTIFY handler
    let bpf_maps = maps::BpfMaps::from_ebpf(&mut bpf)?;
    let db_listener_handle = tokio::spawn({
        let db_url = database_url.clone();
        let maps = bpf_maps.clone();
        async move {
            if let Err(e) = db::listen_for_changes(&db_url, maps).await {
                // listen_for_changes only returns Err on a fatal startup condition
                // (pool creation failure). Panic so the process exits visibly rather
                // than running silently deaf to all domain changes.
                panic!("DB listener fatal error: {e}");
            }
        }
    });

    // Spawn periodic re-resolver
    let resolver_handle = {
        let pool = db_pool.clone();
        let maps = bpf_maps;
        tokio::spawn(async move {
            resolver::run_periodic_resolver(pool, maps).await;
        })
    };

    // Wait for shutdown signal (SIGINT / SIGTERM).
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;
    tokio::select! {
        res = tokio::signal::ctrl_c() => res.context("failed to listen for SIGINT")?,
        _ = sigterm.recv() => {}
    }

    info!("Shutting down...");
    db_listener_handle.abort();
    resolver_handle.abort();

    Ok(())
}
