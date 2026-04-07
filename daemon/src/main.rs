use anyhow::{Context, Result};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

mod db;
mod loader;
mod maps;
mod resolver;

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

    info!("Starting daemon");
    info!("Tunnel interface: {interface_name}");
    info!("WAN interface: {wan_interface}");

    // Load eBPF programs and attach to interfaces
    info!("Loading eBPF programs...");
    let mut bpf = loader::load_and_attach(&interface_name, &wan_interface)?;

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

    info!("Daemon is running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;

    info!("Shutting down...");
    db_listener_handle.abort();
    resolver_handle.abort();

    Ok(())
}
