#![doc = r"
# Image Load Policy

[Microsoft Docs: Block remote images](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference#block-low-integrity-images)

[API Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy)

Example:
```rust
use win_mitigations::image_load::ImageLoadPolicy;
fn main() -> Result<(), windows::core::Error> {
    ImageLoadPolicy::new()
        .set_no_remote_images(true)
        .build()?;
    Ok(())
}
```
"]
#![cfg(windows)]

#[derive(Clone, Copy)]
pub struct ImageLoadPolicy {
    policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
}

impl ImageLoadPolicy {
    /// Creates a new `ImageLoadPolicy` with default settings.
    /// The default policy has all flags set to false.
    #[must_use]
    pub fn new() -> Self {
        ImageLoadPolicy { policy: windows::Win32::System::SystemServices::PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default() }
    }

    /// Builds the policy and applies it to the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy could not be set.
    pub fn build(self) -> Result<(), windows::core::Error> {
        crate::set_process_mitigation_policy(
            windows::Win32::System::Threading::ProcessImageLoadPolicy,
            &self.policy,
        )
    }

    /// Corresponds to the `NoRemoteImages` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_no_remote_images(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) };
        self
    }

    /// Corresponds to the `NoLowMandatoryLabelImages` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_no_low_mandatory_label_images(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 1 };
        self
    }

    /// Corresponds to the `PreferSystem32Images` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_prefer_system32_images(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 2 };
        self
    }

    /// Corresponds to the `AuditNoRemoteImages` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_no_remote_images(&mut self, status: bool) -> &mut Self {
        unsafe { self.policy.Anonymous.Flags |= u32::from(status) << 3 };
        self
    }

    /// Corresponds to the `AuditNoLowMandatoryLabelImages` flag.
    #[allow(clippy::missing_safety_doc)]
    pub fn set_audit_no_low_mandatory_label_images(&mut self, status: bool) -> &mut Self {
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

impl Default for ImageLoadPolicy {
    fn default() -> Self {
        Self::new()
    }
}
