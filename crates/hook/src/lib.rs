#![allow(non_snake_case)]

use std::ffi::{OsStr, c_void};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{copy_nonoverlapping, null};

use windows_sys::Win32::Foundation::{HINSTANCE, HMODULE, TRUE};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, FreeLibraryAndExitThread, GetModuleHandleW,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::{CreateThread, GetCurrentProcess, Sleep};
use windows_sys::core::BOOL;

struct PatchSpec {
    name: &'static str,
    pattern: &'static str,
    opcode_offset: usize,
    replacement: &'static [u8],
}

const XOR_RCX_RCX: [u8; 3] = [0x48, 0x31, 0xC9];
const XOR_RAX_AND_NOP_5: [u8; 5] = [0x48, 0x31, 0xC0, 0x90, 0x90];
const CMP_AL_AL: [u8; 2] = [0x38, 0xC0];

const PATCHES: &[PatchSpec] = &[
    PatchSpec {
        name: "normal recall preserve original",
        pattern: "48 89 CF 48 8B 0A 48 85 C9 0F 84 ?? ?? ?? ?? 44 89 CB 4D 89 C4 48 89 95 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 8B 31",
        opcode_offset: 6,
        replacement: &XOR_RCX_RCX,
    },
    PatchSpec {
        name: "traceless recall preserve original",
        pattern: "48 8B 01 FF 50 28 3C 01 0F 84 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8B 08 48 8B 01 FF 50 30 4C 8B 73 30",
        opcode_offset: 6,
        replacement: &CMP_AL_AL,
    },
    PatchSpec {
        name: "notify recall update preserve original",
        pattern: "48 83 7A 10 00 0F 84 ?? ?? ?? ?? 4C 89 C3 48 89 D7 48 89 CE 48 8D 45 ?? 48 89 00 48 89 40 08 48 83 60 10 00",
        opcode_offset: 0,
        replacement: &XOR_RAX_AND_NOP_5,
    },
];

fn wide_null(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn parse_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    pattern
        .split_whitespace()
        .map(|part| {
            if part == "??" {
                Some(None)
            } else {
                u8::from_str_radix(part, 16).ok().map(Some)
            }
        })
        .collect()
}

unsafe fn search_module_unique(module: HMODULE, pattern: &str) -> Option<*mut u8> {
    let parsed = parse_pattern(pattern)?;
    if parsed.is_empty() {
        return None;
    }

    let mut module_info: MODULEINFO = unsafe { zeroed() };
    let info_ok = unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            module,
            &mut module_info,
            size_of::<MODULEINFO>() as u32,
        )
    };
    if info_ok == 0 {
        return None;
    }

    let base = module_info.lpBaseOfDll.cast::<u8>();
    let size = module_info.SizeOfImage as usize;
    if parsed.len() > size {
        return None;
    }

    let mut found = None;
    let module_start = base as usize;
    let module_end = module_start.checked_add(size)?;
    let mut cursor = module_start;

    while cursor < module_end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let query_size = unsafe {
            VirtualQuery(
                cursor as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if query_size == 0 {
            break;
        }

        let region_start = (mbi.BaseAddress as usize).max(module_start);
        let region_end = (mbi.BaseAddress as usize)
            .saturating_add(mbi.RegionSize)
            .min(module_end);

        if is_readable_committed_region(&mbi) && region_end > region_start {
            let region_len = region_end - region_start;
            if region_len >= parsed.len() {
                'scan: for offset in 0..=(region_len - parsed.len()) {
                    let current = (region_start + offset) as *mut u8;
                    for (index, expected) in parsed.iter().enumerate() {
                        if let Some(byte) = expected {
                            if unsafe { *current.add(index) } != *byte {
                                continue 'scan;
                            }
                        }
                    }
                    if found.is_some() {
                        return None;
                    }
                    found = Some(current);
                }
            }
        }

        let next = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
        if next <= cursor {
            break;
        }
        cursor = next;
    }

    found
}

fn is_readable_committed_region(mbi: &MEMORY_BASIC_INFORMATION) -> bool {
    if mbi.State != MEM_COMMIT {
        return false;
    }
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 {
        return false;
    }

    matches!(
        mbi.Protect & 0xff,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

unsafe fn patch_bytes(address: *mut u8, replacement: &[u8]) -> bool {
    let mut old_protect = 0u32;
    let protect_ok = unsafe {
        VirtualProtect(
            address.cast::<c_void>(),
            replacement.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if protect_ok == 0 {
        return false;
    }

    unsafe {
        copy_nonoverlapping(replacement.as_ptr(), address, replacement.len());
    }

    let mut restored_protect = 0u32;
    unsafe {
        VirtualProtect(
            address.cast::<c_void>(),
            replacement.len(),
            old_protect,
            &mut restored_protect,
        );
        FlushInstructionCache(
            GetCurrentProcess(),
            address.cast::<c_void>(),
            replacement.len(),
        );
    }
    true
}

unsafe fn apply_patch(module: HMODULE, spec: &PatchSpec) -> bool {
    let Some(match_address) = (unsafe { search_module_unique(module, spec.pattern) }) else {
        return false;
    };

    let patch_address = unsafe { match_address.add(spec.opcode_offset) };
    unsafe { patch_bytes(patch_address, spec.replacement) }
}

unsafe fn hook_recall(module: HMODULE) -> usize {
    let mut patched = 0usize;
    for spec in PATCHES {
        let _ = spec.name;
        if unsafe { apply_patch(module, spec) } {
            patched += 1;
        }
    }

    patched
}

unsafe extern "system" fn check_module_thread(param: *mut c_void) -> u32 {
    let self_module = param as HMODULE;
    let wrapper_name = wide_null("wrapper.node");

    for _ in 0..300 {
        let wrapper_module = unsafe { GetModuleHandleW(wrapper_name.as_ptr()) };
        if !wrapper_module.is_null() {
            unsafe {
                hook_recall(wrapper_module);
                FreeLibraryAndExitThread(self_module, 0);
            }
        }
        unsafe {
            Sleep(1000);
        }
    }

    unsafe { FreeLibraryAndExitThread(self_module, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    module: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(module);
            let thread = CreateThread(
                null(),
                0,
                Some(check_module_thread),
                module,
                0,
                null::<u32>() as *mut u32,
            );
            if !thread.is_null() {
                windows_sys::Win32::Foundation::CloseHandle(thread);
            }
        }
    }

    TRUE
}
