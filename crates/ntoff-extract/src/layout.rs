//! Type layout extraction from CodeView records.
//!
//! Two things here are worth more attention than their line count suggests,
//! because both fail quietly (6.3):
//!
//! * **Forward references.** A type name usually resolves to several records,
//!   most of them forward declarations with a size of zero and no field list.
//!   Taking the first match yields an empty type, which is indistinguishable
//!   downstream from "this build dropped the type".
//! * **Anonymous aggregates.** The kernel nests unnamed unions and structs
//!   heavily, and every bitfield in `_EPROCESS` lives inside one. A reader
//!   that does not descend into them reports the wrapper and loses every flag.

use pdb::FallibleIterator;
use std::collections::BTreeMap;

use crate::model::{Member, TypeLayout};

/// A name shared by many unrelated anonymous records, and therefore useless as
/// an identifier.
pub fn is_ambiguous_placeholder(name: &str) -> bool {
    matches!(name, "<unnamed-tag>" | "<anonymous-tag>" | "<unnamed-enum-tag>" | "__unnamed")
        || name.starts_with("__unnamed_")
}

/// Whether a member is a transparent wrapper whose contents belong to the
/// parent at the parent's offset.
///
/// The test is on the **member** name, never the type name. MSVC names the
/// type of any anonymous aggregate `<unnamed-type-X>`, and it does so in two
/// situations that look alike and are not:
///
/// ```c
/// union {
///     ULONG MitigationFlags;
///     struct { ULONG ControlFlowGuardEnabled : 1; ... } MitigationFlagsValues;
///     //                                               ^ named member: opaque
/// };
/// union {
///     ULONG Flags2;
///     struct { ULONG JobNotReallyActive : 1; ... };
///     //                                     ^ no member name: transparent
/// };
/// ```
///
/// Both inner structs have a `<unnamed-type-...>` type name. Keying off that
/// promotes `MitigationFlagsValues`'s bitfields to `_EPROCESS` members that do
/// not exist, and drops the member that does. Both halves of that mistake are
/// silent.
fn is_transparent_member(name: &str) -> bool {
    name.is_empty()
        || name == "__unnamed"
        || name == "<unnamed-tag>"
        || name == "<anonymous-tag>"
        || name.starts_with("__unnamed_")
}

/// `'a` is the borrow of the type stream, deliberately separate from the
/// lifetime of the mapped file behind it. Tying the two together would demand
/// that the borrow outlive the whole PDB, which no caller can arrange.
pub struct TypeIndexMap<'a> {
    finder: pdb::TypeFinder<'a>,
    /// Name to the record that actually carries the definition.
    definitions: BTreeMap<String, pdb::TypeIndex>,
    /// Enumerations live in their own namespace: a struct and an enum can
    /// share a name, and merging them loses one of the two.
    enums: BTreeMap<String, pdb::TypeIndex>,
}

impl<'a> TypeIndexMap<'a> {
    pub fn build<'t>(information: &'a pdb::TypeInformation<'t>) -> pdb::Result<Self> {
        let mut finder = information.finder();
        let mut definitions: BTreeMap<String, pdb::TypeIndex> = BTreeMap::new();
        let mut enums: BTreeMap<String, pdb::TypeIndex> = BTreeMap::new();
        let mut iter = information.iter();

        while let Some(item) = iter.next()? {
            finder.update(&iter);

            if let Ok(pdb::TypeData::Enumeration(enumeration)) = item.parse() {
                let name = enumeration.name.to_string().into_owned();
                if enumeration.properties.forward_reference() {
                    enums.entry(name).or_insert(item.index());
                } else {
                    enums.insert(name, item.index());
                }
                continue;
            }

            let (name, forward, index) = match item.parse() {
                Ok(pdb::TypeData::Class(class)) => (
                    class.name.to_string().into_owned(),
                    class.properties.forward_reference(),
                    item.index(),
                ),
                Ok(pdb::TypeData::Union(union)) => (
                    union.name.to_string().into_owned(),
                    union.properties.forward_reference(),
                    item.index(),
                ),
                _ => continue,
            };

            if forward {
                // Keep it only as a last resort, so a type that appears solely
                // as a declaration is still reported rather than vanishing.
                definitions.entry(name).or_insert(index);
            } else {
                definitions.insert(name, index);
            }
        }

        Ok(Self {
            finder,
            definitions,
            enums,
        })
    }

    pub fn find(&self, index: pdb::TypeIndex) -> pdb::Result<pdb::Item<'a, pdb::TypeIndex>> {
        self.finder.find(index)
    }

    pub fn lookup(&self, name: &str) -> Option<pdb::TypeIndex> {
        self.definitions.get(name).copied()
    }

    pub fn lookup_enum(&self, name: &str) -> Option<pdb::TypeIndex> {
        self.enums.get(name).copied()
    }

    /// Every *addressable* struct and union, for `--types *`.
    ///
    /// Excludes the placeholder names MSVC gives anonymous aggregates that are
    /// not tied to a member: `<unnamed-tag>` and friends are shared by dozens
    /// of unrelated records, so a name-to-index map collapses them into one and
    /// `extract_type` returns a chimera -- members from whichever record was
    /// stored last, size from another. On eighteen Insider builds that produced
    /// a `<unnamed-tag>` whose members ran past its own size.
    ///
    /// They were never useful anyway: nothing can ask for a type whose name
    /// does not identify it. Their contents reach callers through the parent
    /// they are embedded in, which is what flattening is for.
    ///
    /// `<unnamed-type-Foo>` and `<unnamed-enum-Foo>` are kept -- those carry
    /// the member name and do identify one record.
    pub fn all_type_names(&self) -> Vec<String> {
        self.definitions
            .keys()
            .filter(|name| !is_ambiguous_placeholder(name))
            .cloned()
            .collect()
    }

    fn parse(&self, index: pdb::TypeIndex) -> Option<pdb::TypeData<'a>> {
        self.find(index).ok()?.parse().ok()
    }

    /// Size in bytes of whatever `index` denotes.
    ///
    /// Resolved recursively because a member's declared type is frequently a
    /// modifier or an enumeration wrapping the thing that actually has a size.
    pub fn size_of(&self, index: pdb::TypeIndex) -> u32 {
        match self.parse(index) {
            // The finder resolves indices below the stream minimum to builtins
            // without touching the record buffer, so primitives arrive here.
            Some(pdb::TypeData::Primitive(primitive)) => primitive_size(&primitive),
            Some(pdb::TypeData::Class(class)) => {
                self.aggregate_size(index, &class.name.to_string(), class.size as u32, class.properties.forward_reference())
            }
            Some(pdb::TypeData::Union(union)) => {
                self.aggregate_size(index, &union.name.to_string(), union.size as u32, union.properties.forward_reference())
            }
            Some(pdb::TypeData::Enumeration(enumeration)) => self.size_of(enumeration.underlying_type),
            Some(pdb::TypeData::Array(array)) => array.dimensions.last().copied().unwrap_or(0),
            Some(pdb::TypeData::Pointer(pointer)) => u32::from(pointer.attributes.size()),
            Some(pdb::TypeData::Modifier(modifier)) => self.size_of(modifier.underlying_type),
            Some(pdb::TypeData::Bitfield(bitfield)) => self.size_of(bitfield.underlying_type),
            _ => 0,
        }
    }

    /// A member declared against a forward reference records size zero. Follow
    /// the name to the definition, or the member silently becomes zero-sized.
    fn aggregate_size(&self, index: pdb::TypeIndex, name: &str, declared: u32, forward: bool) -> u32 {
        if !forward {
            return declared;
        }
        match self.definitions.get(name) {
            Some(resolved) if *resolved != index => self.size_of(*resolved),
            _ => declared,
        }
    }
}

/// Byte width of a builtin.
///
/// Builtins are encoded in the type index itself rather than stored as
/// records, so there is no record to read a size from and the table has to be
/// written out here.
fn primitive_size(primitive: &pdb::PrimitiveType) -> u32 {
    use pdb::PrimitiveKind::*;

    // A pointer to a primitive is still a pointer, and CodeView states its
    // width in the indirection kind. Sizing it from the *target machine*
    // instead -- which is what an earlier fix did, after hardcoding eight
    // broke x86 -- is wrong in the other direction: `PVOID64` is a 64-bit
    // pointer on x86, and the machine said four. The indirection is the
    // authority and needs no machine type at all.
    if let Some(indirection) = primitive.indirection {
        use pdb::Indirection::*;
        return match indirection {
            Near16 => 2,
            Far16 | Huge16 | Near32 => 4,
            Far32 => 6,
            Near64 => 8,
            Near128 => 16,
        };
    }
    match primitive.kind {
        NoType | Void => 0,
        Char | UChar | RChar | I8 | U8 | Bool8 => 1,
        WChar | RChar16 | Short | UShort | I16 | U16 | Bool16 | F16 => 2,
        RChar32 | Long | ULong | I32 | U32 | F32 | Bool32 | HRESULT => 4,
        Quad | UQuad | I64 | U64 | F64 | Bool64 | Complex32 => 8,
        Octa | UOcta | I128 | U128 | F128 | Complex64 => 16,
        _ => 0,
    }
}

pub fn extract_type(map: &TypeIndexMap<'_>, name: &str) -> Option<TypeLayout> {
    let index = map.lookup(name)?;
    let (size, fields) = match map.find(index).ok()?.parse().ok()? {
        pdb::TypeData::Class(class) => (class.size as u32, class.fields?),
        pdb::TypeData::Union(union) => (union.size as u32, union.fields),
        _ => return None,
    };

    let mut members = Vec::new();
    let mut next_group = 0;
    collect(map, fields, 0, &mut members, 0, 0, &mut next_group);
    members.sort();
    members.dedup();
    Some(TypeLayout { size, members })
}

/// Walks one field list, appending to `members`.
///
/// `base` carries the offset of the enclosing anonymous aggregate so that
/// flattened members report their offset within the outermost type, which is
/// the number a caller actually needs.
///
/// `group` is the id of the outermost anonymous union we descended through, or
/// zero at the top level. Members sharing a nonzero group are the ones allowed
/// to occupy the same bytes; see `Member::union_group`.
fn collect(
    map: &TypeIndexMap<'_>,
    fields: pdb::TypeIndex,
    base: u32,
    members: &mut Vec<Member>,
    depth: u32,
    group: u32,
    next_group: &mut u32,
) {
    // Anonymous nesting in the kernel headers is a handful of levels at most;
    // the bound exists so a malformed or cyclic record cannot spin forever.
    if depth > 16 {
        return;
    }

    let list = match map.find(fields).ok().and_then(|item| item.parse().ok()) {
        Some(pdb::TypeData::FieldList(list)) => list,
        _ => return,
    };

    for field in list.fields {
        let member = match field {
            pdb::TypeData::Member(member) => member,
            // Static members have no instance offset, base classes do not
            // occur in C structs, and nested type declarations carry no
            // storage.
            _ => continue,
        };

        let offset = base + member.offset as u32;
        let member_name = member.name.to_string().into_owned();

        match map
            .find(member.field_type)
            .ok()
            .and_then(|item| item.parse().ok())
        {
            Some(pdb::TypeData::Bitfield(bitfield)) => {
                members.push(Member {
                    offset,
                    name: member_name,
                    size: map.size_of(bitfield.underlying_type),
                    bit_position: u16::from(bitfield.position),
                    bit_count: u16::from(bitfield.length),
                    union_group: group,
                });
            }
            Some(pdb::TypeData::Class(class)) if is_transparent_member(&member_name) => {
                let inner = resolve_fields(
                    map,
                    &class.name.to_string(),
                    class.fields,
                    class.properties.forward_reference(),
                );
                if let Some(inner) = inner {
                    // An anonymous struct shares no storage; it inherits
                    // whatever union scope it was already in.
                    collect(map, inner, offset, members, depth + 1, group, next_group);
                }
            }
            Some(pdb::TypeData::Union(union)) if is_transparent_member(&member_name) => {
                let inner = resolve_fields(
                    map,
                    &union.name.to_string(),
                    Some(union.fields),
                    union.properties.forward_reference(),
                );
                if let Some(inner) = inner {
                    // Only the outermost union defines the scope: members of a
                    // union nested inside another still legitimately overlap
                    // everything in the outer one.
                    let scope = if group == 0 {
                        *next_group += 1;
                        *next_group
                    } else {
                        group
                    };
                    collect(map, inner, offset, members, depth + 1, scope, next_group);
                }
            }
            _ => {
                members.push(Member {
                    offset,
                    name: member_name,
                    size: map.size_of(member.field_type),
                    bit_position: 0,
                    bit_count: 0,
                    union_group: group,
                });
            }
        }
    }
}

/// A nested anonymous aggregate can itself be recorded as a forward reference;
/// the field list then lives on the definition record.
fn resolve_fields(
    map: &TypeIndexMap<'_>,
    name: &str,
    fields: Option<pdb::TypeIndex>,
    forward: bool,
) -> Option<pdb::TypeIndex> {
    if !forward {
        return fields;
    }
    let index = map.lookup(name)?;
    match map.find(index).ok()?.parse().ok()? {
        pdb::TypeData::Class(class) => class.fields,
        pdb::TypeData::Union(union) => Some(union.fields),
        _ => None,
    }
}
