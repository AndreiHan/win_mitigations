#![doc = r"
# Address Space Layout Randomization (ASLR)

[Microsoft Docs: ASLR](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/overview-of-threat-mitigations-in-windows-10#address-space-layout-randomization)

[API Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_aslr_policy)

Example:
```no_run
use win_mitigations::aslr::AslrPolicy;
fn main() -> Result<(), windows::core::Error> {
    AslrPolicy::new()
        .set_enable_high_entropy(true)
        .set_enable_force_relocate_images(true)
        .build()?;
    Ok(())
}
```
"]
#![cfg(windows)]

#[derive(Clone, Copy)]
pub struct AslrPolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_ASLR_POLICY,
}

impl AslrPolicy {
    /// Creates a new `AslrPolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        AslrPolicy {
            policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_ASLR_POLICY::default(
            ),
        }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Safety
    ///
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessASLRPolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `EnableBottomUpRandomization` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_enable_bottom_up_randomization(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `EnableForceRelocateImages` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_enable_force_relocate_images(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 1 };
        self
    }

    /// Corresponds to the `EnableHighEntropy` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_enable_high_entropy(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 2 };
        self
    }

    /// Corresponds to the `DisallowStrippedImages` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_disallow_stripped_images(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 3 };
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

impl Default for AslrPolicy {
    fn default() -> Self {
        Self::new()
    }
}
