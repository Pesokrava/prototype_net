use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use tracing::{info, Level};
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
    let server_ipv6_str =
        std::env::var("SERVER_IPV6").context("SERVER_IPV6 environment variable not set")?;
    let client_ipv6_str =
        std::env::var("CLIENT_IPV6").context("CLIENT_IPV6 environment variable not set")?;

    let server_ipv6: Ipv6Addr = server_ipv6_str
        .parse()
        .context("SERVER_IPV6 is not a valid IPv6 address")?;
    let client_ipv6: Ipv6Addr = client_ipv6_str
        .parse()
        .context("CLIENT_IPV6 is not a valid IPv6 address")?;

    info!("Starting daemon");
    info!("Interface: {interface_name}");
    info!("Server IPv6: {server_ipv6}");
    info!("Client IPv6: {client_ipv6}");

    // Load eBPF programs and attach to interface
    info!("Loading eBPF programs...");
    let mut bpf = loader::load_and_attach(&interface_name, server_ipv6)?;

    // Connect to database
    info!("Connecting to database...");
    let db_pool = db::create_pool(&database_url).await?;

    // Bulk-load all existing domain mappings into BPF maps
    info!("Bulk-loading existing domain mappings into BPF maps...");
    let count = maps::bulk_load_from_db(&mut bpf, &db_pool, client_ipv6).await?;
    info!("Loaded {count} domain mappings into BPF maps");

    // Spawn LISTEN/NOTIFY handler
    let bpf_maps = maps::BpfMaps::from_ebpf(&mut bpf)?;
    let db_listener_handle = {
        let db_url = database_url.clone();
        let maps = bpf_maps.clone();
        tokio::spawn(async move {
            if let Err(e) = db::listen_for_changes(&db_url, maps, client_ipv6).await {
                tracing::error!("DB listener error: {e}");
            }
        })
    };

    // Spawn periodic re-resolver
    let resolver_handle = {
        let pool = db_pool.clone();
        let maps = bpf_maps;
        tokio::spawn(async move {
            resolver::run_periodic_resolver(pool, maps, client_ipv6).await;
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
