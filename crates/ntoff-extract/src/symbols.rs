//! Global symbol RVAs (6.2).
//!
//! This is the half Vergilius does not publish and the half callers most often
//! need: a struct offset is useless without a base to apply it to.
//!
//! Both the global symbol stream and the public symbol stream are consulted.
//! The global stream carries typed data symbols and is preferred; the public
//! stream is a fallback for names that only ever appear as exports.

use pdb::FallibleIterator;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Resolves every requested name in a single pass over each stream. The
/// streams hold hundreds of thousands of records, so per-name scanning would
/// dominate the runtime of the whole extractor.
/// Whether a name is a kernel global someone might actually ask for.
///
/// Taking every public data symbol yields about 18,000 entries, and 7,400 of
/// them are string literals (`??_C@...`). Decorated C++ names, import thunks
/// and compiler internals make up most of the rest. What is left -- around
/// 10,000 plain C identifiers -- is the set that contains
/// `PsInitialSystemProcess`, `PspCreateProcessNotifyRoutine`, `KiServiceTable`
/// and everything else a driver or a forensics tool goes looking for.
fn is_plain_global(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("__imp_")
        && !name.contains(['?', '$', '@'])
}

/// `wanted` empty means every plain global carrying an RVA.
pub fn collect<'s, S: pdb::Source<'s> + 's>(
    pdb: &mut pdb::PDB<'s, S>,
    wanted: &BTreeSet<String>,
) -> pdb::Result<BTreeMap<String, u32>> {
    let take_all = wanted.is_empty();
    let address_map = pdb.address_map()?;
    let mut found: BTreeMap<String, u32> = BTreeMap::new();

    let globals = pdb.global_symbols()?;
    let mut iter = globals.iter();
    while let Some(symbol) = iter.next()? {
        // A stripped public PDB carries almost no `S_GDATA32` records -- the
        // kernel's has none at all. Everything reachable is a public symbol,
        // and the only thing separating a global from a function there is the
        // `code`/`function` flag pair. Filtering on those is what makes
        // "every global" mean 5,000 useful entries rather than 48,000 mostly
        // being functions.
        let (name, offset) = match symbol.parse() {
            Ok(pdb::SymbolData::Data(data)) => (data.name, data.offset),
            Ok(pdb::SymbolData::Public(data)) => {
                if take_all && (data.code || data.function) {
                    continue;
                }
                (data.name, data.offset)
            }
            _ => continue,
        };
        let name = name.to_string();
        if found.contains_key(name.as_ref()) {
            continue;
        }
        if take_all {
            if !is_plain_global(&name) {
                continue;
            }
        } else if !wanted.contains(name.as_ref()) {
            continue;
        }
        if let Some(rva) = offset.to_rva(&address_map) {
            found.insert(name.into_owned(), rva.0);
        }
    }

    Ok(found)
}
