//! Rendering a CodeView type index as a C declaration.
//!
//! A member's offset and size say where it is and how much room it takes. They
//! do not say what it *is*, and "eight bytes at 0x248" is not enough to write a
//! reader against -- `_EX_FAST_REF` and `PVOID` and `LIST_ENTRY *` are all
//! eight bytes and none of them is read the same way.
//!
//! The spelling here is a contract, not a convenience: it goes into the layout
//! hash, and the DIA oracle renders the same indices independently and is
//! diffed against it. So the rules have to be stated rather than left to
//! whatever each library happens to produce.
//!
//! * builtins use their C names as MSVC spells them (`unsigned long`, not
//!   `ULONG` -- the typedef is not in the record)
//! * pointers are `T *`, one space, star last, at every level
//! * arrays are `T[N]` with the element count, not the byte size
//! * `const` and `volatile` lead: `const T`
//! * a function type renders as `T ()`; the parameter list is in a separate
//!   record and no consumer of a struct layout needs it
//! * anything unresolvable is the empty string, never a guess. A wrong type is
//!   worse than an absent one.

use crate::layout::TypeIndexMap;

/// Depth bound. Pointer and modifier chains are short in practice; the bound
/// exists so a cyclic record cannot spin forever, the same reason `collect`
/// has one.
const MAX_DEPTH: u32 = 12;

pub fn render(map: &TypeIndexMap<'_>, index: pdb::TypeIndex) -> String {
    render_at(map, index, 0)
}

fn render_at(map: &TypeIndexMap<'_>, index: pdb::TypeIndex, depth: u32) -> String {
    if depth > MAX_DEPTH {
        return String::new();
    }
    let Some(data) = map.parse_type(index) else {
        return String::new();
    };

    match data {
        pdb::TypeData::Primitive(primitive) => primitive_name(&primitive),
        pdb::TypeData::Class(class) => class.name.to_string().into_owned(),
        pdb::TypeData::Union(union) => union.name.to_string().into_owned(),
        pdb::TypeData::Enumeration(enumeration) => enumeration.name.to_string().into_owned(),

        pdb::TypeData::Pointer(pointer) => {
            // A pointer to a function is not `T () *`. Appending the star to a
            // rendered function type reads as a function returning a pointer,
            // which is a different type; C spells this one `T (*)()` and so do
            // we, at every level of nesting.
            let target = render_at(map, pointer.underlying_type, depth + 1);
            if target.is_empty() {
                return String::new();
            }
            // CodeView puts a pointer's own const/volatile in the pointer
            // record's attributes rather than in a modifier wrapping it, and
            // the qualifier belongs after the star: `T * volatile` is a
            // volatile pointer, `volatile T *` is a pointer to volatile, and
            // they are different types.
            let mut suffix = String::new();
            if pointer.attributes.is_const() {
                suffix.push_str(" const");
            }
            if pointer.attributes.is_volatile() {
                suffix.push_str(" volatile");
            }
            match map.parse_type(pointer.underlying_type) {
                Some(pdb::TypeData::Procedure(_)) | Some(pdb::TypeData::MemberFunction(_)) => {
                    format!("{}{suffix}", target.replacen(" ()", " (*)()", 1))
                }
                _ => format!("{target} *{suffix}"),
            }
        }

        pdb::TypeData::Modifier(modifier) => {
            let inner = render_at(map, modifier.underlying_type, depth + 1);
            if inner.is_empty() {
                return String::new();
            }
            // Both can be set; `const volatile T` is the order MSVC prints.
            let mut out = String::new();
            if modifier.constant {
                out.push_str("const ");
            }
            if modifier.volatile {
                out.push_str("volatile ");
            }
            out.push_str(&inner);
            out
        }

        pdb::TypeData::Array(array) => {
            let element = render_at(map, array.element_type, depth + 1);
            if element.is_empty() {
                return String::new();
            }
            // `dimensions` holds byte extents, not counts. An element size of
            // zero would divide by zero and, worse, would silently produce a
            // plausible-looking dimension, so it renders unsized instead.
            let stride = map.size_of(array.element_type);
            match array.dimensions.last() {
                Some(&bytes) if stride > 0 => format!("{element}[{}]", bytes / stride),
                _ => format!("{element}[]"),
            }
        }

        pdb::TypeData::Bitfield(bitfield) => render_at(map, bitfield.underlying_type, depth + 1),

        pdb::TypeData::Procedure(procedure) => {
            let returns = procedure
                .return_type
                .map(|r| render_at(map, r, depth + 1))
                .unwrap_or_default();
            if returns.is_empty() { String::new() } else { format!("{returns} ()") }
        }
        pdb::TypeData::MemberFunction(function) => {
            let returns = render_at(map, function.return_type, depth + 1);
            if returns.is_empty() { String::new() } else { format!("{returns} ()") }
        }

        _ => String::new(),
    }
}

/// C names for the builtins.
///
/// Builtins live in the type index rather than in a record, so as with
/// `primitive_size` the table has to be written out. Indirection is handled by
/// the caller-visible star: a primitive index can itself denote a pointer.
fn primitive_name(primitive: &pdb::PrimitiveType) -> String {
    use pdb::PrimitiveKind::*;

    let base = match primitive.kind {
        NoType => "",
        Void => "void",
        Char => "char",
        UChar => "unsigned char",
        RChar => "char",
        RChar16 => "char16_t",
        RChar32 => "char32_t",
        WChar => "wchar_t",
        // CodeView separates `char`/`I8` and `unsigned char`/`U8`; DIA
        // reports both pairs as one basic type of length one and cannot tell
        // them apart. Spelling them the same way here means the two readers
        // can only ever agree -- the alternative is a gate that fails on a
        // distinction neither the oracle nor any consumer can act on.
        I8 => "char",
        U8 => "unsigned char",
        Short | I16 => "short",
        UShort | U16 => "unsigned short",
        Long => "long",
        ULong => "unsigned long",
        I32 => "int",
        U32 => "unsigned int",
        Quad | I64 => "__int64",
        UQuad | U64 => "unsigned __int64",
        Octa | I128 => "__int128",
        UOcta | U128 => "unsigned __int128",
        F16 => "half",
        F32 => "float",
        F64 => "double",
        F128 => "long double",
        Complex32 => "_Complex float",
        Complex64 => "_Complex double",
        Bool8 => "bool",
        Bool16 => "bool16",
        Bool32 => "bool32",
        Bool64 => "bool64",
        HRESULT => "HRESULT",
        _ => "",
    };

    if base.is_empty() {
        return String::new();
    }
    // A primitive index can carry indirection of its own -- `PVOID64` is one
    // index, not a pointer record wrapping void.
    match primitive.indirection {
        Some(_) => format!("{base} *"),
        None => base.to_string(),
    }
}
