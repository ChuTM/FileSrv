//! `rekey` — re-seal every encrypted blob's DEK from the OLD SERVER_SECRET to a
//! NEW one, in place, without touching the file payloads.
//!
//! This is the efficient half of rotating SERVER_SECRET: envelope encryption
//! keeps each blob's DEK sealed under KEK = SHA-256(SERVER_SECRET) in the blob
//! header, so we only unwrap the DEK with the old KEK and re-wrap it with the
//! new one. The body ciphertext never changes, so rotation is O(1) per file and
//! safe.
//!
//! Usage:
//!   rekey --blobs <dir> --old <old-secret> --new <new-secret> [--dry-run]
//!
//! Legacy plaintext blobs (no TSFS magic) are left untouched.

use std::fs;
use std::io::Read;
use std::path::Path;
use filesrv::crypto::{blob_rekey, looks_like_encrypted_blob};

fn main() {
    let mut blobs: Option<String> = None;
    let mut old: Option<String> = None;
    let mut new: Option<String> = None;
    let mut dry = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--blobs" => { blobs = Some(args[i + 1].clone()); i += 2; }
            "--old" => { old = Some(args[i + 1].clone()); i += 2; }
            "--new" => { new = Some(args[i + 1].clone()); i += 2; }
            "--dry-run" => { dry = true; i += 1; }
            "-h" | "--help" => {
                println!("Usage: rekey --blobs <dir> --old <old-secret> --new <new-secret> [--dry-run]");
                return;
            }
            other => { eprintln!("error: unknown argument: {other}"); std::process::exit(2); }
        }
    }

    let (blobs, old, new) = match (blobs, old, new) {
        (Some(b), Some(o), Some(n)) => (b, o, n),
        _ => { eprintln!("error: --blobs, --old and --new are all required"); std::process::exit(2); }
    };

    let dir = Path::new(&blobs);
    if !dir.is_dir() {
        eprintln!("error: blobs dir does not exist: {}", dir.display());
        std::process::exit(2);
    }

    let old_b = old.as_bytes();
    let new_b = new.as_bytes();
    let mut total = 0usize;
    let mut rekeyed = 0usize;
    let mut skipped = 0usize; // legacy plaintext (no TSFS magic)
    let mut unwrappable = 0usize; // envelope but cannot be unwrapped (wrong/older secret or bad header)
    let mut errors = 0usize; // hard I/O failures

    if dry {
        println!("==> DRY RUN — no files will be written");
    }
    println!("==> re-keying blobs under {}", dir.display());

    walk(
        dir, old_b, new_b, dry,
        &mut total, &mut rekeyed, &mut skipped, &mut unwrappable, &mut errors,
    );

    println!(
        "==> done: total={total} rekeyed={rekeyed} skipped_legacy={skipped} \
unwrappable={unwrappable} errors={errors}"
    );
    if unwrappable > 0 {
        eprintln!(
            "!! {unwrappable} blob(s) carry the envelope magic but could not be unwrapped with \
the given OLD secret — they were likely encrypted under an older/rotated SERVER_SECRET and \
cannot be re-keyed. They were left untouched."
        );
    }
    if errors > 0 {
        std::process::exit(1);
    }
}

fn walk(
    dir: &Path,
    old: &[u8],
    new: &[u8],
    dry: bool,
    total: &mut usize,
    rekeyed: &mut usize,
    skipped: &mut usize,
    unwrappable: &mut usize,
    errors: &mut usize,
) {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("!! cannot read dir {}: {e}", dir.display());
            *errors += 1;
            return;
        }
    };
    for entry in rd {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let p = entry.path();
        if p.is_dir() {
            walk(&p, old, new, dry, total, rekeyed, skipped, unwrappable, errors);
        } else if p.is_file() {
            process(&p, old, new, dry, total, rekeyed, skipped, unwrappable, errors);
        }
    }
}

fn process(
    path: &Path,
    old: &[u8],
    new: &[u8],
    dry: bool,
    total: &mut usize,
    rekeyed: &mut usize,
    skipped: &mut usize,
    unwrappable: &mut usize,
    errors: &mut usize,
) {
    let mut data = Vec::new();
    if fs::File::open(path)
        .and_then(|mut f| f.read_to_end(&mut data))
        .is_err()
    {
        eprintln!("!! cannot read {}", path.display());
        *errors += 1;
        return;
    }
    *total += 1;
    if data.len() < 5 || !looks_like_encrypted_blob(&data[..5]) {
        *skipped += 1; // legacy plaintext blob — leave as-is
        return;
    }
    let rekeyed_blob = match blob_rekey(old, new, &data) {
        Some(b) => b,
        None => {
            // Has the magic but could not be unwrapped with the OLD secret:
            // likely encrypted under an older/rotated secret, or a bad header.
            // Leave the file untouched and warn, so a rotate over mixed-key
            // data does not fail part-way.
            eprintln!("!! unwrappable (wrong/older secret or bad header), left as-is: {}", path.display());
            *unwrappable += 1;
            return;
        }
    };
    if dry {
        println!("  [dry] would re-key: {}", path.display());
        *rekeyed += 1;
        return;
    }
    // Atomic write: temp file in the same directory, then rename over.
    let tmp = path.with_file_name(format!(
        ".{}.rekey.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("blob"),
        std::process::id()
    ));
    if fs::write(&tmp, &rekeyed_blob).is_err() || fs::rename(&tmp, path).is_err() {
        eprintln!("!! cannot write re-keyed blob: {}", path.display());
        let _ = fs::remove_file(&tmp);
        *errors += 1;
        return;
    }
    *rekeyed += 1;
}
