#![cfg(windows)]
#[derive(Clone, Copy)]
pub struct FontDisablePolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_FONT_DISABLE_POLICY,
}

impl FontDisablePolicy {
    /// Creates a new `FontDisablePolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        FontDisablePolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_FONT_DISABLE_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessFontDisablePolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `DisableNonSystemFonts` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_disable_non_system_fonts(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `AuditNonSystemFontLoading` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_non_system_font_loading(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 1 };
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

impl Default for FontDisablePolicy {
    fn default() -> Self {
        Self::new()
    }
}
