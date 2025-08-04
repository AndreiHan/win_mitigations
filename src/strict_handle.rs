#![cfg(windows)]
#[derive(Clone, Copy)]
pub struct StrictHandlePolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
}

impl StrictHandlePolicy {
    /// Creates a new `StrictHandlePolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        StrictHandlePolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessStrictHandleCheckPolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `RaiseExceptionOnInvalidHandleReference` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_raise_exception_on_invalid_handle_reference(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `HandleExceptionsPermanentlyEnabled` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_handle_exceptions_permanently_enabled(&mut self, status: bool) -> &mut Self {
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

impl Default for StrictHandlePolicy {
    fn default() -> Self {
        Self::new()
    }
}
