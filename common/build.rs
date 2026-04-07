use std::{env, fs, path::PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    address: Address,
    vip_pool: VipPool,
    xfrm: Xfrm,
}

#[derive(Deserialize)]
struct Address {
    synthetic_prefix_bytes: [u8; 4],
}

#[derive(Deserialize)]
struct VipPool {
    discriminator_bytes: [u8; 4],
}

#[derive(Deserialize)]
struct Xfrm {
    if_id: u32,
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let contract_path = manifest.parent().unwrap().join("contract.toml");

    // Re-run build.rs whenever contract.toml changes.
    println!("cargo:rerun-if-changed={}", contract_path.display());

    let src = fs::read_to_string(&contract_path).expect(
        "contract.toml not found at workspace root — \
         run from the workspace root or set CARGO_MANIFEST_DIR correctly",
    );
    let c: Contract = toml::from_str(&src).expect("failed to parse contract.toml");

    let b = c.address.synthetic_prefix_bytes;
    let d = c.vip_pool.discriminator_bytes;
    let if_id = c.xfrm.if_id;

    let code = format!(
        "/// Prefix bytes for synthetic IPv6 addresses: fd00:abcd::/32.\n\
         /// Generated from `contract.toml` — do not edit by hand.\n\
         pub const SYNTHETIC_PREFIX: [u8; 4] = \
             [{b0:#04x}, {b1:#04x}, {b2:#04x}, {b3:#04x}];\n\n\
         /// Pool discriminator bytes: bytes 4–7 of every client VIP.\n\
         /// Generated from `contract.toml` — do not edit by hand.\n\
         pub const VIP_POOL_DISCRIMINATOR: [u8; 4] = \
             [{d0:#04x}, {d1:#04x}, {d2:#04x}, {d3:#04x}];\n\n\
         /// XFRM interface if_id for the IPSec child SA.\n\
         /// Generated from `contract.toml` — do not edit by hand.\n\
         pub const XFRM_IF_ID: u32 = {if_id};\n",
        b0 = b[0],
        b1 = b[1],
        b2 = b[2],
        b3 = b[3],
        d0 = d[0],
        d1 = d[1],
        d2 = d[2],
        d3 = d[3],
        if_id = if_id,
    );

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("contract.rs");
    fs::write(&out, code).expect("failed to write contract.rs to OUT_DIR");
}
