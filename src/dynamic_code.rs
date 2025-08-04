#![cfg(windows)]
#[derive(Clone, Copy)]
pub struct DynamicCodePolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
}

impl DynamicCodePolicy {
    /// Creates a new `DynamicCodePolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        DynamicCodePolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessDynamicCodePolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `ProhibitDynamicCode` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_prohibit_dynamic_code(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `AllowThreadOptOut` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_allow_thread_opt_out(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 1 };
        self
    }

    /// Corresponds to the `AllowRemoteDowngrade` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_allow_remote_downgrade(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 2 };
        self
    }

    /// Corresponds to the `AuditProhibitDynamicCode` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_prohibit_dynamic_code(&mut self, status: bool) -> &mut Self {
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

impl Default for DynamicCodePolicy {
    fn default() -> Self {
        Self::new()
    }
}
