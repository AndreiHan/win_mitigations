#![doc = r"
# Binary Signature Policy (Code Integrity Guard)

[API Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy)

Example:
```rust
use win_mitigations::binary_signature::BinarySignaturePolicy;
fn main() -> Result<(), windows::core::Error> {
    let mut policy = BinarySignaturePolicy::new();
    policy.set_microsoft_signed_only(true);
    policy.build()?;
    Ok(())
}
```
"]
#![cfg(windows)]

#[derive(Clone, Copy)]
pub struct BinarySignaturePolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
}

impl BinarySignaturePolicy {
    /// Creates a new `BinarySignaturePolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        BinarySignaturePolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessSignaturePolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `MicrosoftSignedOnly` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_microsoft_signed_only(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `StoreSignedOnly` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_store_signed_only(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 1 };
        self
    }

    /// Corresponds to the `MitigationOptIn` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_mitigation_opt_in(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 2 };
        self
    }

    /// Corresponds to the `AuditMicrosoftSignedOnly` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_microsoft_signed_only(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 3 };
        self
    }

    /// Corresponds to the `AuditStoreSignedOnly` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_store_signed_only(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 4 };
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

impl Default for BinarySignaturePolicy {
    fn default() -> Self {
        Self::new()
    }
}
