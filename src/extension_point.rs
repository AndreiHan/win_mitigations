#![doc = r"
# Extension Point Policy

[Microsoft Docs: Disable extension points](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference#disable-extension-points)

[API Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_extension_point_disable_policy)

Example:
```rust
use win_mitigations::extension_point::ExtensionPointPolicy;
fn main() -> Result<(), windows::core::Error> {
    ExtensionPointPolicy::new()
        .set_disable_extension_points(true)
        .build()?;
    Ok(())
}
```
"]
#![cfg(windows)]

#[derive(Clone, Copy)]
pub struct ExtensionPointPolicy {
    policy:
        windows::Win32::System::SystemServices::PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
}

impl ExtensionPointPolicy {
    /// Creates a new `ExtensionPointPolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        ExtensionPointPolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessExtensionPointDisablePolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `DisableExtensionPoints` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_disable_extension_points(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Sets a custom flag in the policy.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it allows arbitrary modification of the policy flags.
    pub unsafe fn custom_set(&mut self, flag: u32, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << flag };
        self
    }
}

impl Default for ExtensionPointPolicy {
    fn default() -> Self {
        Self::new()
    }
}
