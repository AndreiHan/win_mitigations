
<p align="center">
    <img src="https://raw.githubusercontent.com/AndreiHan/win_mitigations/master/assets/logo.png" alt="win_mitigations" width="120" />
</p>

# win_mitigations

<p align="center">
    <a href="https://crates.io/crates/win_mitigations"><img src="https://img.shields.io/crates/v/win_mitigations.svg?style=flat-square" alt="Crates.io"></a>
    <a href="https://docs.rs/win_mitigations"><img src="https://img.shields.io/docsrs/win_mitigations?style=flat-square" alt="docs.rs"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg?style=flat-square"></a>
    <!-- Add CI badge if available -->
</p>

---

<p align="center">
    <b>Safe, ergonomic Rust wrappers for Windows process mitigation policies.</b><br>
    <sub>Harden your Windows processes against exploitation and unwanted behaviors.</sub>
</p>

---

## Features

- Configure Windows process mitigation policies using ergonomic Rust types
- Builder-style APIs for each mitigation
- Safe wrappers over Windows API
- No unsafe code required for typical usage

## Supported Policies

- **ASLR** ([src/aslr.rs](src/aslr.rs))
- **Binary Signature** ([src/binary_signature.rs](src/binary_signature.rs))
- **Child Process** ([src/child_process.rs](src/child_process.rs))
- **Dynamic Code** ([src/dynamic_code.rs](src/dynamic_code.rs))
- **Extension Point** ([src/extension_point.rs](src/extension_point.rs))
- **Font Disable** ([src/font_disable.rs](src/font_disable.rs))
- **Image Load** ([src/image_load.rs](src/image_load.rs))
- **Strict Handle** ([src/strict_handle.rs](src/strict_handle.rs))

## Installation

Add to your `Cargo.toml`:

```toml
win_mitigations = "0.1.1"
```

## Usage

See [API documentation](https://docs.rs/win_mitigations) for full details.

### Enable ASLR and Strict Handle Checks

```rust
use win_mitigations::aslr::AslrPolicy;
use win_mitigations::strict_handle::StrictHandlePolicy;

fn main() -> Result<(), windows::core::Error> {
    AslrPolicy::new()
        .set_enable_high_entropy(true)
        .set_enable_force_relocate_images(true)
        .build()?;

    StrictHandlePolicy::new()
        .set_raise_exception_on_invalid_handle_reference(true)
        .set_handle_exceptions_permanently_enabled(true)
        .build()?;
    Ok(())
}
```

### Disable Extension Points

```rust
use win_mitigations::extension_point::ExtensionPointPolicy;

fn main() -> Result<(), windows::core::Error> {
    ExtensionPointPolicy::new()
        .set_disable_extension_points(true)
        .build()?;
    Ok(())
}
```

### Restrict Child Process Creation

```rust
use win_mitigations::child_process::ChildProcessPolicy;

fn main() -> Result<(), windows::core::Error> {
    ChildProcessPolicy::new()
        .set_no_child_process_creation(true)
        .build()?;
    Ok(())
}
```

## Documentation

- [API Docs (docs.rs)](https://docs.rs/win_mitigations)
- [src/lib.rs](src/lib.rs) — main API
- Individual modules for each mitigation policy

## License

Licensed under MIT
