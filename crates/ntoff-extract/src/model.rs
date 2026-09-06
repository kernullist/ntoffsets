//! The serialized form, byte-identical to what the DIA oracle emits.
//!
//! Field order, key order and member order all matter: the comparison against
//! DIA is a diff, and a difference in presentation would read as a difference
//! in the data.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Member {
    pub offset: u32,
    pub name: String,
    pub size: u32,
    pub bit_position: u16,
    pub bit_count: u16,
    /// The member's declared type, spelled by `typename`.
    ///
    /// Part of the layout contract and therefore hashed: offset and size say
    /// where a member is and how wide, not how to read it, and `_EX_FAST_REF`,
    /// `PVOID` and `_LIST_ENTRY *` are all eight bytes.
    ///
    /// Empty when the record cannot be resolved. Never a guess.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Identifies the outermost anonymous union a member was flattened out of,
    /// or zero for a member that sits directly in the struct.
    ///
    /// Not part of the layout contract: it is absent from the layout hash and
    /// the DIA oracle cannot produce it, because DIA's flattened view reports
    /// every member's parent as the outer type and loses the union entirely.
    /// It exists so the self-consistency check can tell members that legally
    /// share storage from members that overlap because the parser lost track
    /// (13.1) -- and that check has to run on Linux CI, where DIA cannot.
    pub union_group: u32,
}

#[derive(Serialize)]
pub struct TypeLayout {
    pub size: u32,
    pub members: Vec<Member>,
}

#[derive(Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EnumConstant {
    pub name: String,
    pub value: i64,
}

#[derive(Serialize)]
pub struct EnumDef {
    pub size: u32,
    pub constants: Vec<EnumConstant>,
}

#[derive(Serialize)]
pub struct Extraction {
    pub extractor: &'static str,
    pub pdb_key: String,
    pub types: BTreeMap<String, TypeLayout>,
    #[serde(default)]
    pub enums: BTreeMap<String, EnumDef>,
    pub rvas: BTreeMap<String, u32>,
    pub missing_types: Vec<String>,
    pub missing_symbols: Vec<String>,
    pub missing_enums: Vec<String>,
}
