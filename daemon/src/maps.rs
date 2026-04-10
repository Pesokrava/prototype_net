use std::net::Ipv6Addr;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::IterableMap;
use aya::maps::hash_map::HashMap as BpfHashMap;
use common::NatEntry;
use sqlx::PgPool;
use tracing::info;

/// Thread-safe wrapper around BPF maps for concurrent access.
#[derive(Clone)]
pub struct BpfMaps {
    inner: Arc<Mutex<BpfMapsInner>>,
}

struct BpfMapsInner {
    nat_map_fd: i32,
}

impl BpfMaps {
    /// Extract map file descriptors from the loaded eBPF object.
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let nat_map = bpf.map("NAT_MAP").context("NAT_MAP not found")?;
        // Get fd via TryFrom<&Map> → HashMap<&MapData, ..> → IterableMap::map() → fd()
        let nat_ref: BpfHashMap<&aya::maps::MapData, u32, NatEntry> =
            BpfHashMap::try_from(nat_map).context("failed to cast NAT_MAP")?;
        let nat_fd = nat_ref.map().fd().as_fd().as_raw_fd();

        Ok(Self {
            inner: Arc::new(Mutex::new(BpfMapsInner { nat_map_fd: nat_fd })),
        })
    }

    /// Insert a NAT mapping: domain_id → origin IPv6.
    pub fn insert_nat_entry(&self, domain_id: u32, origin_ipv6: Ipv6Addr) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let entry = NatEntry {
            origin_ipv6: origin_ipv6.octets(),
        };

        // Re-open the map from the fd
        use std::os::fd::BorrowedFd;
        let fd = unsafe { BorrowedFd::borrow_raw(inner.nat_map_fd) };
        let map_data = aya::maps::MapData::from_fd(fd.try_clone_to_owned()?)
            .context("failed to open NAT_MAP from fd")?;
        let mut map: BpfHashMap<_, u32, NatEntry> =
            BpfHashMap::try_from(aya::maps::Map::HashMap(map_data))
                .context("failed to cast NAT_MAP")?;
        map.insert(domain_id, entry, 0)
            .context("failed to insert into NAT_MAP")?;
        Ok(())
    }

    /// Remove entries for a given domain_id from NAT_MAP.
    #[allow(dead_code)]
    pub fn remove_nat_entry(&self, domain_id: u32) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        use std::os::fd::BorrowedFd;
        let fd = unsafe { BorrowedFd::borrow_raw(inner.nat_map_fd) };
        let map_data = aya::maps::MapData::from_fd(fd.try_clone_to_owned()?)
            .context("failed to open NAT_MAP from fd")?;
        let mut map: BpfHashMap<_, u32, NatEntry> =
            BpfHashMap::try_from(aya::maps::Map::HashMap(map_data))
                .context("failed to cast NAT_MAP")?;
        let _ = map.remove(&domain_id); // ignore if not present
        Ok(())
    }
}

/// Bulk-load all domain mappings from the database into BPF maps.
pub async fn bulk_load_from_db(bpf: &mut Ebpf, pool: &PgPool) -> Result<usize> {
    // (domain_id, origin_ipv6_text, synthetic_ipv6_text)
    let rows: Vec<(i32, String, String)> = sqlx::query_as(
        r#"SELECT domain_id, host(origin_ipv6)::text, host(synthetic_ipv6)::text FROM domains"#,
    )
    .fetch_all(pool)
    .await
    .context("failed to fetch all domains for bulk load")?;

    let nat_map_data = bpf.map_mut("NAT_MAP").context("NAT_MAP not found")?;
    let mut nat_map: BpfHashMap<&mut aya::maps::MapData, u32, NatEntry> =
        BpfHashMap::try_from(nat_map_data).context("failed to cast NAT_MAP")?;

    let count = rows.len();

    for (domain_id, origin_ipv6_text, _synthetic) in &rows {
        let origin: Ipv6Addr = origin_ipv6_text
            .parse()
            .context("invalid origin_ipv6 in DB")?;
        let entry = NatEntry {
            origin_ipv6: origin.octets(),
        };
        nat_map
            .insert(*domain_id as u32, entry, 0)
            .context("failed to insert into NAT_MAP during bulk load")?;
    }

    info!("Bulk-loaded {count} entries into NAT_MAP");
    Ok(count)
}
