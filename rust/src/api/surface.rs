//! Manifest of the bridge surface a consumer can reach, and the checks that
//! keep it from reaching an unauthenticated vault by accident.
//!
//! The generated files are read as text, so what this establishes is a property
//! of the committed generated code, not of a freshly generated build. Stale
//! generated files would leave these scans looking at the wrong text; the
//! repository regenerates and diffs separately.
//!
//! Within that limit: an entry added, renamed, moved to a new module, or given a
//! path or key parameter fails here before anyone has to notice it by hand.

use std::collections::BTreeSet;

use crate::api::evfs::types::UnsafeLegacyEvfsPolicy;
use crate::frb_generated::CstDecode;

const GENERATED_RUST: &str = include_str!("../frb_generated.rs");
const GENERATED_DART: &str = include_str!("../../../lib/src/rust/frb_generated.dart");
const GENERATED_IO_DART: &str = include_str!("../../../lib/src/rust/frb_generated.io.dart");
const GENERATED_WEB_DART: &str = include_str!("../../../lib/src/rust/frb_generated.web.dart");
const GENERATED_EVFS_DART: &str = include_str!("../../../lib/src/rust/api/evfs.dart");
const GENERATED_STREAMING_DART: &str = include_str!("../../../lib/src/rust/api/streaming.dart");

const BARREL_DART: &str = include_str!("../../../lib/m_security.dart");
const VAULT_SERVICE_DART: &str = include_str!("../../../lib/src/evfs/vault_service.dart");
const STREAMING_SERVICE_DART: &str =
    include_str!("../../../lib/src/streaming/streaming_service.dart");
const COMPRESSION_SERVICE_DART: &str =
    include_str!("../../../lib/src/compression/compression_service.dart");

/// Every hand-written file in `api::evfs`, so a second policy check or a second
/// grant cannot hide in a sibling module.
const EVFS_SOURCES: [(&str, &str); 3] = [
    ("api/evfs/mod.rs", include_str!("evfs/mod.rs")),
    ("api/evfs/types.rs", include_str!("evfs/types.rs")),
    ("api/evfs/helpers.rs", include_str!("evfs/helpers.rs")),
];

const EVFS_SOURCE: &str = EVFS_SOURCES[0].1;
const EVFS_TYPES_SOURCE: &str = EVFS_SOURCES[1].1;

/// What keeps one reachable entry away from an unauthenticated vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Takes a vault path and a key, so the caller's policy enum decides.
    Policy,
    /// Takes the opaque handle, which only an opted-in call can produce, and no
    /// vault path or key of its own.
    Handle,
    /// Takes neither a vault path, a key nor a handle. The one entry using it
    /// does read a caller-named file, which is why the check below forbids the
    /// vault-path parameter rather than every path.
    NoVaultAccess,
}

struct Entry {
    /// Suffix of the C symbol and of the wasm entry, minus the module prefix.
    wire: &'static str,
    /// Method on the generated `RustLibApi`, which is the only dispatcher route.
    api_method: &'static str,
    /// Free function in the per-module Dart file. `None` for a method on an
    /// opaque type, which the generator puts on the class instead.
    dart_fn: Option<&'static str>,
    gate: Gate,
}

/// Every bridge entry under `api::evfs` and `api::streaming`.
///
/// A new entry in either module fails the three set comparisons below, and an
/// entry smuggled into a *new* module fails the module comparison, so together
/// they are what proves no converter, archive or encrypted-stream entry came
/// back under any name.
const MANIFEST: [Entry; 19] = [
    Entry {
        wire: "types__VaultHandle_health",
        api_method: "crateApiEvfsTypesVaultHandleHealth",
        dart_fn: None,
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_capacity",
        api_method: "crateApiEvfsVaultCapacity",
        dart_fn: Some("vaultCapacity"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_close",
        api_method: "crateApiEvfsVaultClose",
        dart_fn: Some("vaultClose"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_create",
        api_method: "crateApiEvfsVaultCreate",
        dart_fn: Some("vaultCreate"),
        gate: Gate::Policy,
    },
    Entry {
        wire: "vault_defragment",
        api_method: "crateApiEvfsVaultDefragment",
        dart_fn: Some("vaultDefragment"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_delete",
        api_method: "crateApiEvfsVaultDelete",
        dart_fn: Some("vaultDelete"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_flush",
        api_method: "crateApiEvfsVaultFlush",
        dart_fn: Some("vaultFlush"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_health",
        api_method: "crateApiEvfsVaultHealth",
        dart_fn: Some("vaultHealth"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_list",
        api_method: "crateApiEvfsVaultList",
        dart_fn: Some("vaultList"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_open",
        api_method: "crateApiEvfsVaultOpen",
        dart_fn: Some("vaultOpen"),
        gate: Gate::Policy,
    },
    Entry {
        wire: "vault_read",
        api_method: "crateApiEvfsVaultRead",
        dart_fn: Some("vaultRead"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_read_parallel",
        api_method: "crateApiEvfsVaultReadParallel",
        dart_fn: Some("vaultReadParallel"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_read_stream",
        api_method: "crateApiEvfsVaultReadStream",
        dart_fn: Some("vaultReadStream"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_rename_segment",
        api_method: "crateApiEvfsVaultRenameSegment",
        dart_fn: Some("vaultRenameSegment"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_resize",
        api_method: "crateApiEvfsVaultResize",
        dart_fn: Some("vaultResize"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_rotate_key",
        api_method: "crateApiEvfsVaultRotateKey",
        dart_fn: Some("vaultRotateKey"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_write",
        api_method: "crateApiEvfsVaultWrite",
        dart_fn: Some("vaultWrite"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "vault_write_file",
        api_method: "crateApiEvfsVaultWriteFile",
        dart_fn: Some("vaultWriteFile"),
        gate: Gate::Handle,
    },
    Entry {
        wire: "stream_hash_file",
        api_method: "crateApiStreamingStreamHashFile",
        dart_fn: Some("streamHashFile"),
        gate: Gate::NoVaultAccess,
    },
];

/// Lowercased Rust and Dart spellings of the entries this release removed.
const REMOVED_NEEDLES: [&str; 12] = [
    "vault_export",
    "vaultexport",
    "vault_import",
    "vaultimport",
    "stream_encrypt_file",
    "streamencryptfile",
    "stream_decrypt_file",
    "streamdecryptfile",
    "stream_compress_encrypt_file",
    "streamcompressencryptfile",
    "stream_decrypt_decompress_file",
    "streamdecryptdecompressfile",
];

const GENERATED_SOURCES: [(&str, &str); 6] = [
    ("rust/src/frb_generated.rs", GENERATED_RUST),
    ("lib/src/rust/frb_generated.dart", GENERATED_DART),
    ("lib/src/rust/frb_generated.io.dart", GENERATED_IO_DART),
    ("lib/src/rust/frb_generated.web.dart", GENERATED_WEB_DART),
    ("lib/src/rust/api/evfs.dart", GENERATED_EVFS_DART),
    ("lib/src/rust/api/streaming.dart", GENERATED_STREAMING_DART),
];

/// Files that carry the C symbols and wasm entries, one name per entry.
const WIRE_SOURCES: [(&str, &str); 3] = [
    ("rust/src/frb_generated.rs", GENERATED_RUST),
    ("lib/src/rust/frb_generated.io.dart", GENERATED_IO_DART),
    ("lib/src/rust/frb_generated.web.dart", GENERATED_WEB_DART),
];

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Collect what follows every `wire__crate__api__<module>__` occurrence.
///
/// The generator spells the C symbol, the wasm entry, the internal dispatcher
/// body and the Dart lookup pointer with the same suffix, so the `_impl` and
/// `Ptr` tails are dropped to leave one name per entry. Every real entry is
/// snake_case and none ends in either, and the manifest comparison would catch
/// one that did.
fn wire_entries(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for module in ["evfs", "streaming"] {
        let prefix = format!("wire__crate__api__{module}__");
        let mut rest = source;
        while let Some(at) = rest.find(&prefix) {
            rest = &rest[at + prefix.len()..];
            let end = rest.find(|c: char| !is_name_char(c)).unwrap_or(rest.len());
            let name = rest[..end]
                .trim_end_matches("Ptr")
                .trim_end_matches("_impl");
            if !name.is_empty() {
                found.insert(name.to_string());
            }
        }
    }
    found
}

/// Collect the first path segment after `wire__crate__api__`, which is the
/// module a bridge entry lives in.
fn wire_modules(source: &str) -> BTreeSet<String> {
    const PREFIX: &str = "wire__crate__api__";
    let mut found = BTreeSet::new();
    let mut rest = source;

    while let Some(at) = rest.find(PREFIX) {
        rest = &rest[at + PREFIX.len()..];
        let end = rest.find(|c: char| !is_name_char(c)).unwrap_or(rest.len());
        if let Some(module) = rest[..end].split("__").next() {
            if !module.is_empty() {
                found.insert(module.to_string());
            }
        }
    }

    found
}

/// Collect every `crateApiEvfs*` / `crateApiStreaming*` dispatcher method.
fn api_methods(source: &str) -> BTreeSet<String> {
    all_api_methods(source)
        .into_iter()
        .filter(|name| name.starts_with("crateApiEvfs") || name.starts_with("crateApiStreaming"))
        .collect()
}

/// Collect every dispatcher method the bridge declares, in any module.
fn all_api_methods(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for token in source.split(|c: char| !is_name_char(c)) {
        if token.starts_with("crateApi") {
            found.insert(token.to_string());
        }
    }
    found
}

/// Collect the free functions a per-module generated Dart file declares.
fn dart_functions(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in source.lines() {
        if !(line.starts_with("Future<") || line.starts_with("Stream<")) {
            continue;
        }
        let Some(open) = line.find('(') else { continue };
        let Some(name) = line[..open].rsplit(' ').next() else {
            continue;
        };
        if !name.is_empty() {
            found.insert(name.to_string());
        }
    }
    found
}

/// The parameter text of a generated Dart or Rust declaration.
///
/// The parentheses are matched, so a nested one in a parameter type cannot
/// truncate the text and leave a gate check reading half a signature.
fn parameters_of(source: &str, name: &str) -> String {
    let needle = format!(" {name}(");
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("{name} is not declared in the generated source"))
        + needle.len();
    let rest = &source[start..];

    let mut depth = 1usize;
    let mut end = None;
    for (at, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(at);
                    break;
                }
            }
            _ => (),
        }
    }

    let end = end.unwrap_or_else(|| panic!("{name} has no closing parenthesis"));
    rest[..end].replace('\n', " ")
}

/// Drop whole-line comments so a scan reads what the file does, not what it
/// says about itself.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The whole body of a function, found by matching braces rather than by
/// looking for a closing brace in column one, so a nested item cannot hide the
/// rest of it from a scan.
fn item_body(source: &str, opening: &str) -> String {
    let start = source
        .find(opening)
        .unwrap_or_else(|| panic!("{opening} is not in the source"));
    let rest = &source[start..];
    let open_brace = rest
        .find('{')
        .unwrap_or_else(|| panic!("{opening} has no body"));

    let mut depth = 0usize;
    for (at, c) in rest[open_brace..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[..open_brace + at].to_string();
                }
            }
            _ => (),
        }
    }

    panic!("{opening} does not close");
}

#[test]
fn every_generated_source_still_looks_generated() {
    for (name, source) in GENERATED_SOURCES {
        let mentions_an_entry = MANIFEST.iter().any(|entry| {
            source.contains(entry.wire)
                || source.contains(entry.api_method)
                || entry.dart_fn.is_some_and(|f| source.contains(f))
        });

        assert!(
            mentions_an_entry,
            "{name} no longer looks like a generated bridge file, so these scans prove nothing"
        );
    }
}

#[test]
fn the_wire_entries_match_the_manifest() {
    let expected: BTreeSet<String> = MANIFEST.iter().map(|e| e.wire.to_string()).collect();

    for (name, source) in WIRE_SOURCES {
        assert_eq!(
            wire_entries(source),
            expected,
            "{name} exposes a different set of vault entries than the manifest"
        );
    }
}

/// A module comparison as well as an entry comparison, because a restored
/// archive or converter entry in a brand new module would satisfy every
/// evfs-and-streaming scan on its own.
#[test]
fn the_bridge_has_no_module_beyond_the_known_six() {
    let expected: BTreeSet<String> = [
        "compression",
        "encryption",
        "evfs",
        "hashing",
        "kdf",
        "streaming",
    ]
    .iter()
    .map(|m| (*m).to_string())
    .collect();

    for (name, source) in WIRE_SOURCES {
        assert_eq!(
            wire_modules(source),
            expected,
            "{name} carries a bridge module the manifest never considered"
        );
    }
}

#[test]
fn the_dispatcher_routes_match_the_manifest() {
    let expected: BTreeSet<String> = MANIFEST.iter().map(|e| e.api_method.to_string()).collect();

    assert_eq!(
        api_methods(GENERATED_DART),
        expected,
        "lib/src/rust/frb_generated.dart routes a different set of vault calls than the manifest"
    );
}

#[test]
fn the_module_dart_exports_match_the_manifest() {
    let expected: BTreeSet<String> = MANIFEST
        .iter()
        .filter_map(|e| e.dart_fn.map(str::to_string))
        .collect();

    let mut found = dart_functions(GENERATED_EVFS_DART);
    found.extend(dart_functions(GENERATED_STREAMING_DART));

    assert_eq!(
        found, expected,
        "the generated Dart exports differ from the manifest"
    );
}

#[test]
fn every_entry_needs_an_opt_in_created_handle_or_the_policy_enum() {
    for entry in &MANIFEST {
        let params = parameters_of(GENERATED_DART, entry.api_method);

        match entry.gate {
            Gate::Policy => {
                assert!(
                    params.contains("UnsafeLegacyEvfsPolicy unsafeLegacyPolicy"),
                    "{} takes a vault path but no policy: {params}",
                    entry.api_method
                );
                // The C symbol carries the decision too, so a caller cannot
                // reach the entry point through the raw wire without it.
                let native = parameters_of(
                    GENERATED_RUST,
                    &format!("frbgen_m_security_wire__crate__api__evfs__{}", entry.wire),
                );
                assert!(
                    native.contains("unsafe_legacy_policy: i32"),
                    "the {} symbol does not take the policy: {native}",
                    entry.wire
                );
            }
            Gate::Handle => {
                assert!(
                    params.contains("VaultHandle handle") || params.contains("VaultHandle that"),
                    "{} reaches a vault without a handle: {params}",
                    entry.api_method
                );
                // A handle-gated entry that also took a vault path or a master
                // key would be a second way in, so neither may appear.
                assert!(
                    !params.contains("String path"),
                    "{} takes a vault path as well as a handle: {params}",
                    entry.api_method
                );
                assert!(
                    !params.contains("List<int> key"),
                    "{} takes a master key as well as a handle: {params}",
                    entry.api_method
                );
            }
            Gate::NoVaultAccess => {
                assert!(
                    !params.contains("VaultHandle"),
                    "{} takes a vault handle after all: {params}",
                    entry.api_method
                );
                assert!(
                    !params.contains("String path"),
                    "{} takes a vault path after all: {params}",
                    entry.api_method
                );
                assert!(
                    !params.to_lowercase().contains("key"),
                    "{} takes a key after all: {params}",
                    entry.api_method
                );
            }
        }
    }
}

/// The whole bridge, not just the vault modules: an entry that takes a path or a
/// key and is not listed here is one the manifest above never considered.
#[test]
fn no_unlisted_bridge_entry_takes_a_path_or_a_key() {
    // shouldSkipCompression looks at a name's extension and does no I/O, and the
    // two cipher constructors take a caller buffer, not a vault key. Everything
    // else here is in the manifest above.
    const TAKES_A_PATH: [&str; 5] = [
        "crateApiCompressionShouldSkipCompression",
        "crateApiEvfsVaultCreate",
        "crateApiEvfsVaultOpen",
        "crateApiEvfsVaultWriteFile",
        "crateApiStreamingStreamHashFile",
    ];
    const TAKES_A_KEY: [&str; 5] = [
        "crateApiEncryptionCreateAes256Gcm",
        "crateApiEncryptionCreateChacha20Poly1305",
        "crateApiEvfsVaultCreate",
        "crateApiEvfsVaultOpen",
        "crateApiEvfsVaultRotateKey",
    ];

    // Matched on the parameter's type plus any name ending in Path or Key, so a
    // returning `vaultExport({..., String exportPath, List<int> wrappingKey})`
    // is caught as readily as one that reuses the old names.
    fn parameter_names(params: &str, dart_type: &str) -> Vec<String> {
        params
            .split(',')
            .map(|part| part.trim().trim_start_matches('{').trim())
            .map(|part| part.strip_prefix("required ").unwrap_or(part))
            .filter_map(|part| part.strip_prefix(dart_type))
            .map(|name| name.trim().trim_end_matches('}').trim().to_string())
            .collect()
    }

    let mut with_path = Vec::new();
    let mut with_key = Vec::new();
    for name in all_api_methods(GENERATED_DART) {
        let params = parameters_of(GENERATED_DART, &name);

        let paths = parameter_names(&params, "String ");
        if paths
            .iter()
            .any(|p| p == "path" || p.to_lowercase().ends_with("path"))
        {
            with_path.push(name.clone());
        }

        let keys = parameter_names(&params, "List<int> ");
        if keys
            .iter()
            .any(|k| k == "key" || k.to_lowercase().ends_with("key"))
        {
            with_key.push(name);
        }
    }
    with_path.sort();
    with_path.dedup();
    with_key.sort();
    with_key.dedup();

    assert_eq!(
        with_path, TAKES_A_PATH,
        "a bridge entry takes a filesystem path without being accounted for"
    );
    assert_eq!(
        with_key, TAKES_A_KEY,
        "a bridge entry takes a key without being accounted for"
    );
}

#[test]
fn the_removed_format_entries_are_absent_from_every_generated_file() {
    for (name, source) in GENERATED_SOURCES {
        let lowercased = source.to_lowercase();
        for needle in REMOVED_NEEDLES {
            assert!(
                !lowercased.contains(needle),
                "{name} still exposes a removed format entry (matched {needle})"
            );
        }
    }
}

#[test]
fn the_dart_vault_wrappers_default_to_denial() {
    // Flipping either default is the regression this catches.
    let wrapper = code_only(VAULT_SERVICE_DART);

    assert_eq!(
        wrapper.matches("UnsafeLegacyEvfsPolicy.deny").count(),
        2,
        "VaultService.create and VaultService.open must each default to denial"
    );
    assert!(
        !wrapper.contains("UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2"),
        "the wrapper opts in on the caller's behalf"
    );
}

#[test]
fn the_disabled_dart_methods_reach_no_bridge_function() {
    let services = [
        ("lib/src/evfs/vault_service.dart", VAULT_SERVICE_DART),
        (
            "lib/src/streaming/streaming_service.dart",
            STREAMING_SERVICE_DART,
        ),
        (
            "lib/src/compression/compression_service.dart",
            COMPRESSION_SERVICE_DART,
        ),
    ];

    for (name, source) in services {
        let lowercased = source.to_lowercase();
        for needle in REMOVED_NEEDLES {
            assert!(
                !lowercased.contains(needle),
                "{name} still calls a removed bridge function (matched {needle})"
            );
        }
        assert!(
            source.contains("CryptoError.disabledFormat"),
            "{name} has no disabled-format result to return"
        );
    }
}

#[test]
fn one_policy_check_stands_between_a_caller_and_the_vault() {
    // Counted over every file in the module and over code only, so a mint added
    // in a sibling file or hidden in a comment does not slip through.
    let decisions: usize = EVFS_SOURCES
        .iter()
        .map(|(_, source)| code_only(source).matches(".authorize()").count())
        .sum();

    assert_eq!(
        decisions, 2,
        "creation and opening take exactly one policy decision each, and nothing else takes one"
    );

    let mints: usize = EVFS_SOURCES
        .iter()
        .map(|(_, source)| code_only(source).matches("_sealed").count())
        .sum();

    // Two mentions: the field declaration and the one struct literal that fills
    // it, both inside `mod grant`.
    assert_eq!(
        mints, 2,
        "the grant's private field is mentioned somewhere other than its own module"
    );
    assert_eq!(
        code_only(EVFS_TYPES_SOURCE).matches("_sealed").count(),
        2,
        "the grant is built outside api/evfs/types.rs"
    );

    for (name, source) in EVFS_SOURCES {
        let code = code_only(source);
        for switch in [
            "env::var",
            "env::vars",
            "option_env!",
            "env!",
            "var_os",
            "getenv",
        ] {
            assert!(
                !code.contains(switch),
                "{name} reads {switch}, so something other than the enum can opt in"
            );
        }
    }
}

/// The public barrel is the surface a consumer actually imports, so it has to
/// name the policy enum and must not re-export the raw bridge modules.
#[test]
fn the_barrel_exports_the_policy_and_not_the_bridge() {
    let barrel = code_only(BARREL_DART);

    assert!(
        barrel.contains("UnsafeLegacyEvfsPolicy"),
        "a consumer cannot name the policy through the barrel"
    );
    for module in [
        "src/rust/api/evfs.dart",
        "src/rust/api/streaming.dart",
        "src/rust/frb_generated.io.dart",
    ] {
        assert!(
            !barrel.contains(module),
            "the barrel re-exports {module}, which bypasses the wrappers"
        );
    }
}

#[test]
fn the_policy_check_precedes_every_filesystem_call() {
    for opening in [
        "fn vault_create_guarded(",
        "fn vault_open_guarded(",
        "fn vault_create(",
        "fn vault_open(",
    ] {
        let body = item_body(EVFS_SOURCE, opening);
        // Broad on purpose: the runtime oracles cannot see a discarded
        // read-only lookup, so this list is what stands behind the claim that
        // nothing reaches the path before the decision.
        for io in [
            "OpenOptions",
            "File::",
            "VaultLock",
            "WriteAheadLog",
            "VaultMmap",
            "Mmap",
            "fs::",
            "fs4",
            "libc::",
            "Path",
            "metadata",
            "canonicalize",
            "exists",
            "read_dir",
            "read_to_string",
            "create_dir",
            "remove_file",
            "rename",
            ".open(",
        ] {
            assert!(
                !body.contains(io),
                "{opening} mentions {io} before handing the decision on"
            );
        }
    }

    // The guard has to come first: an early return before it leaves the
    // caller's key unwiped.
    for opening in ["fn vault_create_guarded(", "fn vault_open_guarded("] {
        let body = item_body(EVFS_SOURCE, opening);
        let guard = body
            .find("KeyGuard::new")
            .expect("the guarded entry point does not guard the key");
        let check = body
            .find(".authorize()")
            .expect("the guarded entry point does not check the policy");
        assert!(guard < check, "{opening} checks the policy before guarding");
    }
}

#[test]
fn a_zero_policy_discriminant_decodes_to_denial() {
    // Zero is what a zero-filled wire field carries, and denial is the variant
    // the generator maps it to because `Deny` is declared first.
    let decoded: UnsafeLegacyEvfsPolicy = CstDecode::cst_decode(0i32);

    assert_eq!(decoded, UnsafeLegacyEvfsPolicy::Deny);
}

#[test]
fn an_out_of_range_policy_discriminant_never_decodes_to_the_opt_in() {
    for raw in [-1i32, 2, 7, i32::MAX, i32::MIN] {
        let decoded =
            std::panic::catch_unwind(|| -> UnsafeLegacyEvfsPolicy { CstDecode::cst_decode(raw) });

        match decoded {
            // The generated decoder panics rather than returning a typed error,
            // which the release profile turns into an abort. That is a crash,
            // not a denial: what it establishes is only that no value outside
            // 0 and 1 reaches vault code, and it is what the generator already
            // does for every other enum on this bridge.
            Err(_) => (),
            Ok(policy) => assert_eq!(
                policy,
                UnsafeLegacyEvfsPolicy::Deny,
                "discriminant {raw} decoded to something other than denial"
            ),
        }
    }
}

/// The malformed-discriminant path has to leave the filesystem alone too, which
/// the decode test above cannot see on its own.
#[test]
fn a_malformed_policy_discriminant_touches_no_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .join("malformed.vault")
        .to_string_lossy()
        .to_string();
    let before = std::fs::read_dir(dir.path()).expect("read tempdir").count();

    for raw in [-1i32, 2, 7, i32::MAX] {
        let attempt = std::panic::catch_unwind(|| {
            let policy: UnsafeLegacyEvfsPolicy = CstDecode::cst_decode(raw);
            crate::api::evfs::vault_create(
                path.clone(),
                vec![0xAA; 32],
                "aes-256-gcm".into(),
                1024 * 1024,
                policy,
            )
            .map(|_| ())
        });

        assert!(
            attempt.is_err() || attempt.is_ok_and(|outcome| outcome.is_err()),
            "discriminant {raw} created a vault"
        );
    }

    assert!(!std::path::Path::new(&path).exists(), "a vault was written");
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("read tempdir").count(),
        before,
        "a malformed discriminant left something behind"
    );
}
