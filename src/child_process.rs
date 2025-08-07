#![doc = r"
# Child Process Policy

[API Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_child_process_policy)

Example:
```rust
use win_mitigations::child_process::ChildProcessPolicy;
fn main() -> Result<(), windows::core::Error> {
    ChildProcessPolicy::new()
        .set_no_child_process_creation(true)
        .build()?;
    Ok(())
}
```
"]
#![cfg(windows)]

/// # Child Process Policy
///
/// [Microsoft Docs: Don't allow child processes](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference#disable-win32k-system-calls)
/// [API Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_child_process_policy)
///
/// Example:
/// ```rust
/// use win_mitigations::child_process::ChildProcessPolicy;
/// fn main() -> Result<(), windows::core::Error> {
///     ChildProcessPolicy::new()
///         .set_no_child_process_creation(true)
///         .build()?;
///     Ok(())
/// }
/// ```
#[derive(Clone, Copy)]
pub struct ChildProcessPolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
}

impl ChildProcessPolicy {
    /// Creates a new `ChildProcessPolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        ChildProcessPolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessChildProcessPolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `NoChildProcessCreation` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_no_child_process_creation(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `AuditNoChildProcessCreation` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_no_child_process_creation(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 1 };
        self
    }

    /// Corresponds to the `AllowSecureProcessCreation` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_allow_secure_process_creation(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 2 };
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

impl Default for ChildProcessPolicy {
    fn default() -> Self {
        Self::new()
    }
}
