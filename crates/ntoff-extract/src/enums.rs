//! Enumerations (`LF_ENUM`).
//!
//! The extractor ignored these entirely, which left a real gap: an offset tells
//! you where `_EPROCESS.Protection` lives, and `PS_PROTECTED_TYPE` tells you
//! what the byte there means. Code that checks a process protection level, a
//! pool type or a wait reason needs the constant, and hard-coding it is the
//! same per-build guesswork the offsets exist to remove.
//!
//! They are cheap. A kernel PDB holds around 410 enumerations and 3,900
//! constants, and unlike RVAs they belong in the content-addressed layout --
//! enum values change far less often than they stay the same.

use pdb::FallibleIterator;
use std::collections::BTreeMap;

use crate::layout::TypeIndexMap;
use crate::model::{EnumConstant, EnumDef};

/// Read a numeric leaf as the value it represents.
///
/// `Variant::U8` needs care. The only leaf the `pdb` crate turns into `U8` is
/// `LF_CHAR`, which CodeView defines as **signed**, and the crate hands back
/// the raw byte: `ArbiterRequestUndefined`, which is `-1`, arrives as `255`.
/// Everything else maps honestly -- a small non-negative value is stored inline
/// as `U16`, and `LF_USHORT`/`LF_ULONG`/`LF_UQUADWORD` really are unsigned.
///
/// The consequence of getting this wrong is quiet: a caller comparing a field
/// against `-1` for "undefined" never matches, and nothing raises an error.
/// The DIA oracle caught it on the first run of the enum extractor.
fn constant_value(value: &pdb::Variant) -> i64 {
    match *value {
        pdb::Variant::U8(v) => i64::from(v as i8),
        pdb::Variant::I8(v) => i64::from(v),
        pdb::Variant::I16(v) => i64::from(v),
        pdb::Variant::I32(v) => i64::from(v),
        pdb::Variant::I64(v) => v,
        pdb::Variant::U16(v) => i64::from(v),
        pdb::Variant::U32(v) => i64::from(v),
        pdb::Variant::U64(v) => v as i64,
    }
}

pub fn extract_enum(map: &TypeIndexMap<'_>, name: &str) -> Option<EnumDef> {
    let index = map.lookup_enum(name)?;
    let enumeration = match map.find(index).ok()?.parse().ok()? {
        pdb::TypeData::Enumeration(enumeration) => enumeration,
        _ => return None,
    };

    let mut constants = Vec::new();
    collect(map, enumeration.fields, &mut constants, 0);
    constants.sort_by(|a, b| a.value.cmp(&b.value).then_with(|| a.name.cmp(&b.name)));
    constants.dedup();

    Some(EnumDef {
        size: map.size_of(enumeration.underlying_type),
        constants,
    })
}

fn collect(
    map: &TypeIndexMap<'_>,
    fields: pdb::TypeIndex,
    constants: &mut Vec<EnumConstant>,
    depth: u32,
) {
    if depth > 8 {
        return;
    }
    let list = match map.find(fields).ok().and_then(|item| item.parse().ok()) {
        Some(pdb::TypeData::FieldList(list)) => list,
        _ => return,
    };

    for field in list.fields {
        if let pdb::TypeData::Enumerate(constant) = field {
            constants.push(EnumConstant {
                name: constant.name.to_string().into_owned(),
                value: constant_value(&constant.value),
            });
        }
    }

    // A field list longer than one record continues in another; dropping the
    // continuation silently truncates the larger enums.
    if let Some(next) = list.continuation {
        collect(map, next, constants, depth + 1);
    }
}

/// Every enumeration in the stream that carries a definition.
pub fn all_enum_names(information: &pdb::TypeInformation<'_>) -> pdb::Result<Vec<String>> {
    let mut names: BTreeMap<String, ()> = BTreeMap::new();
    let mut iter = information.iter();
    while let Some(item) = iter.next()? {
        if let Ok(pdb::TypeData::Enumeration(enumeration)) = item.parse() {
            let name = enumeration.name.to_string();
            if !enumeration.properties.forward_reference()
                && !crate::layout::is_ambiguous_placeholder(&name)
            {
                names.insert(name.into_owned(), ());
            }
        }
    }
    Ok(names.into_keys().collect())
}
