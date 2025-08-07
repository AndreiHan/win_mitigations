#![cfg(windows)]
#![doc = include_str!("../readme.md")]
pub mod aslr;
pub mod binary_signature;
pub mod child_process;
pub mod dynamic_code;
pub mod extension_point;
pub mod font_disable;
pub mod image_load;
pub mod strict_handle;

#[inline]
/// Sets the process mitigation policy for the current process.
/// This function is a wrapper around the Windows API function `SetProcessMitigationPolicy`.
/// # Errors
/// Returns an error if the policy cannot be set.
pub fn set_process_mitigation_policy<T>(
    policy: windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY,
    policy_flags: &T,
) -> Result<(), windows::core::Error> {
    unsafe {
        windows::Win32::System::Threading::SetProcessMitigationPolicy(
            policy,
            std::ptr::from_ref(policy_flags).cast::<core::ffi::c_void>(),
            std::mem::size_of_val(policy_flags),
        )
    }
}
