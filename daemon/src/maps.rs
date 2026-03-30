use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use aya::Ebpf;
use common::{NatEntry, ReverseEntry};
use sqlx::PgPool;
use tracing::info;

/// Thread-safe wrapper around BPF maps for concurrent access.
#[derive(Clone)]
pub struct BpfMaps {
    inner: Arc<Mutex<BpfMapsInner>>,
}

struct BpfMapsInner {
    nat_map_fd: i32,
    reverse_map_fd: i32,
}

impl BpfMaps {
    /// Extract map file descriptors from the loaded eBPF object.
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let nat_map = bpf
            .map("NAT_MAP")
            .context("NAT_MAP not found")?;
        let nat_fd = nat_map.fd().as_fd().as_raw_fd();

        let reverse_map = bpf
            .map("REVERSE_MAP")
            .context("REVERSE_MAP not found")?;
        let reverse_fd = reverse_map.fd().as_fd().as_raw_fd();

        Ok(Self {
            inner: Arc::new(Mutex::new(BpfMapsInner {
                nat_map_fd: nat_fd,
                reverse_map_fd: reverse_fd,
            })),
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
        let mut map: BpfHashMap<_, u32, NatEntry> = BpfHashMap::try_from(map_data)
            .context("failed to cast NAT_MAP")?;
        map.insert(domain_id, entry, 0)
            .context("failed to insert into NAT_MAP")?;
        Ok(())
    }

    /// Insert a reverse mapping: origin IPv6 → (domain_id, client IPv6).
    pub fn insert_reverse_entry(
        &self,
        origin_ipv6: Ipv6Addr,
        domain_id: u32,
        client_ipv6: Ipv6Addr,
    ) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let key = origin_ipv6.octets();
        let entry = ReverseEntry {
            domain_id,
            _pad: 0,
            client_ipv6: client_ipv6.octets(),
        };

        use std::os::fd::BorrowedFd;
        let fd = unsafe { BorrowedFd::borrow_raw(inner.reverse_map_fd) };
        let map_data = aya::maps::MapData::from_fd(fd.try_clone_to_owned()?)
            .context("failed to open REVERSE_MAP from fd")?;
        let mut map: BpfHashMap<_, [u8; 16], ReverseEntry> = BpfHashMap::try_from(map_data)
            .context("failed to cast REVERSE_MAP")?;
        map.insert(key, entry, 0)
            .context("failed to insert into REVERSE_MAP")?;
        Ok(())
    }

    /// Remove entries for a given domain_id from NAT_MAP.
    pub fn remove_nat_entry(&self, domain_id: u32) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        use std::os::fd::BorrowedFd;
        let fd = unsafe { BorrowedFd::borrow_raw(inner.nat_map_fd) };
        let map_data = aya::maps::MapData::from_fd(fd.try_clone_to_owned()?)
            .context("failed to open NAT_MAP from fd")?;
        let mut map: BpfHashMap<_, u32, NatEntry> = BpfHashMap::try_from(map_data)
            .context("failed to cast NAT_MAP")?;
        let _ = map.remove(&domain_id); // ignore if not present
        Ok(())
    }
}

use std::os::fd::AsRawFd;

/// Bulk-load all domain mappings from the database into BPF maps.
pub async fn bulk_load_from_db(bpf: &mut Ebpf, pool: &PgPool) -> Result<usize> {
    let rows = sqlx::query!(
        r#"SELECT domain_id, host(origin_ipv6)::text as "origin_ipv6!", host(synthetic_ipv6)::text as "synthetic_ipv6!" FROM domains"#
    )
    .fetch_all(pool)
    .await
    .context("failed to fetch all domains for bulk load")?;

    let nat_map_data = bpf
        .map_mut("NAT_MAP")
        .context("NAT_MAP not found")?;
    let mut nat_map: BpfHashMap<&mut aya::maps::MapData, u32, NatEntry> =
        BpfHashMap::try_from(nat_map_data).context("failed to cast NAT_MAP")?;

    let count = rows.len();

    for row in &rows {
        let origin: Ipv6Addr = row
            .origin_ipv6
            .parse()
            .context("invalid origin_ipv6 in DB")?;
        let entry = NatEntry {
            origin_ipv6: origin.octets(),
        };
        nat_map
            .insert(row.domain_id as u32, entry, 0)
            .context("failed to insert into NAT_MAP during bulk load")?;
    }

    // For REVERSE_MAP we also need to load — but we don't have client_ipv6 stored yet
    // (that would come from the VPN session). For v1, the reverse map is populated
    // with a placeholder client IPv6 that gets filled in by the daemon when the
    // VPN tunnel info is available. For now, we load NAT_MAP only during bulk load.
    // REVERSE_MAP entries are inserted when domain_changes notifications arrive.

    info!("Bulk-loaded {count} entries into NAT_MAP");
    Ok(count)
}
