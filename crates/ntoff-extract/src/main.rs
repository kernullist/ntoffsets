//! Extracts curated kernel type layouts and global symbol RVAs from a PDB.
//!
//! This is the extractor that ships. It runs on a Linux CI runner with nothing
//! installed but a Rust toolchain, which is the whole reason it exists rather
//! than the DIA path (3). Its output is checked against DIA on Windows, and
//! DIA wins every disagreement.
//!
//!     ntoff-extract --pdb <path> --types <a,b,c> --symbols <x,y> --out <file>

mod enums;
mod layout;
mod model;
mod symbols;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::PathBuf;

use model::Extraction;

struct Args {
    pdb: PathBuf,
    types: Vec<String>,
    enums: Vec<String>,
    symbols: Vec<String>,
    out: Option<PathBuf>,
    pdb_key: String,
}

fn parse_args() -> Result<Args, String> {
    let mut pdb = None;
    let mut types = Vec::new();
    let mut enums = Vec::new();
    let mut symbols = Vec::new();
    let mut out = None;
    let mut pdb_key = String::new();

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--pdb" => pdb = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--key" => pdb_key = value()?,
            "--types" => types = split_list(&value()?),
            "--enums" => enums = split_list(&value()?),
            "--symbols" => symbols = split_list(&value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    Ok(Args {
        pdb: pdb.ok_or("--pdb is required")?,
        types,
        enums,
        symbols,
        out,
        pdb_key,
    })
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("ntoff-extract: {message}");
            std::process::exit(2);
        }
    };

    match run(args) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("ntoff-extract: {error}");
            std::process::exit(1);
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(&args.pdb)?;
    let mut pdb = pdb::PDB::open(file)?;

    // `*` means everything the stream holds; an explicit list means exactly
    // that list. Both are useful: a driver build wants five symbols, a
    // database wants all of them.
    let all_symbols = args.symbols.iter().any(|s| s == "*");
    let wanted: BTreeSet<String> = if all_symbols {
        BTreeSet::new()
    } else {
        args.symbols.iter().cloned().collect()
    };
    let rvas = symbols::collect(&mut pdb, &wanted)?;

    let information = pdb.type_information()?;
    let map = layout::TypeIndexMap::build(&information)?;

    let requested_types: Vec<String> = if args.types.iter().any(|t| t == "*") {
        map.all_type_names()
    } else {
        args.types.clone()
    };
    let requested_enums: Vec<String> = if args.enums.iter().any(|e| e == "*") {
        enums::all_enum_names(&information)?
    } else {
        args.enums.clone()
    };

    let mut enum_defs = BTreeMap::new();
    let mut missing_enums = Vec::new();
    for name in &requested_enums {
        match enums::extract_enum(&map, name) {
            Some(extracted) => {
                enum_defs.insert(name.clone(), extracted);
            }
            None => missing_enums.push(name.clone()),
        }
    }

    let mut types = BTreeMap::new();
    let mut missing_types = Vec::new();
    for name in &requested_types {
        match layout::extract_type(&map, name) {
            Some(extracted) => {
                types.insert(name.clone(), extracted);
            }
            None => missing_types.push(name.clone()),
        }
    }

    let missing_symbols: Vec<String> = if all_symbols {
        Vec::new()
    } else {
        args.symbols
            .iter()
            .filter(|name| !rvas.contains_key(*name))
            .cloned()
            .collect()
    };

    let extraction = Extraction {
        extractor: "rust-pdb",
        pdb_key: args.pdb_key,
        types,
        enums: enum_defs,
        rvas,
        missing_types,
        missing_symbols,
        missing_enums,
    };

    let json = serde_json::to_string_pretty(&extraction)?;
    match args.out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, json)?;
            eprintln!(
                "wrote {} ({} types, {} enums, {} symbols)",
                path.display(),
                extraction.types.len(),
                extraction.enums.len(),
                extraction.rvas.len()
            );
        }
        None => println!("{json}"),
    }

    Ok(())
}
