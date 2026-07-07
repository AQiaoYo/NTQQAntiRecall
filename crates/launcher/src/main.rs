#![windows_subsystem = "windows"]

use std::ffi::{OsStr, c_void};
use std::mem::{size_of, transmute, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, CreateRemoteThread,
    GetExitCodeThread, INFINITE, LPTHREAD_START_ROUTINE, PROCESS_INFORMATION, ResumeThread,
    STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

fn wide_null(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn show_error(message: &str) {
    let title = wide_null("NapCatWinBootMain");
    let body = wide_null(message);
    unsafe {
        MessageBoxW(
            null_mut(),
            body.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn last_error(context: &str) -> String {
    format!("{context}, GetLastError={}", unsafe { GetLastError() })
}

unsafe fn close_handle(handle: HANDLE) {
    if !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    wide_null(path.as_os_str())
}

fn exe_dir() -> Result<PathBuf, String> {
    let exe_path = std::env::current_exe().map_err(|err| format!("current_exe failed: {err}"))?;
    exe_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("cannot get parent directory: {}", exe_path.display()))
}

fn trim_registry_exe_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let path_text = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split_once('"').map(|(path, _)| path)?
    } else if let Some(index) = trimmed.to_ascii_lowercase().find(".exe") {
        &trimmed[..index + 4]
    } else {
        trimmed.split_once(',').map_or(trimmed, |(path, _)| path)
    };

    let path = PathBuf::from(path_text.trim());
    if path.exists() { Some(path) } else { None }
}

unsafe fn query_registry_string(root: HKEY, subkey: &str, value_name: &str) -> Option<String> {
    for wow64_flag in [KEY_WOW64_32KEY, KEY_WOW64_64KEY, 0] {
        let mut key = null_mut();
        let subkey_w = wide_null(subkey);
        let open_result =
            unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ | wow64_flag, &mut key) };
        if open_result != ERROR_SUCCESS {
            continue;
        }

        let value_name_w = wide_null(value_name);
        let mut value_type: REG_VALUE_TYPE = 0;
        let mut byte_len = 0u32;
        let size_result = unsafe {
            RegQueryValueExW(
                key,
                value_name_w.as_ptr(),
                null_mut(),
                &mut value_type,
                null_mut(),
                &mut byte_len,
            )
        };
        if size_result != ERROR_SUCCESS || byte_len < 2 {
            unsafe {
                RegCloseKey(key);
            }
            continue;
        }

        let mut buffer = vec![0u16; (byte_len as usize + 1) / 2];
        let read_result = unsafe {
            RegQueryValueExW(
                key,
                value_name_w.as_ptr(),
                null_mut(),
                &mut value_type,
                buffer.as_mut_ptr().cast(),
                &mut byte_len,
            )
        };
        unsafe {
            RegCloseKey(key);
        }

        if read_result != ERROR_SUCCESS {
            continue;
        }

        let nul_index = buffer
            .iter()
            .position(|ch| *ch == 0)
            .unwrap_or(buffer.len());
        return Some(String::from_utf16_lossy(&buffer[..nul_index]));
    }

    None
}

fn qq_from_registry() -> Option<PathBuf> {
    const QQ_UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\QQ";
    let roots = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER];

    for root in roots {
        for value_name in ["DisplayIcon", "UninstallString"] {
            let Some(value) =
                (unsafe { query_registry_string(root, QQ_UNINSTALL_KEY, value_name) })
            else {
                continue;
            };

            if let Some(path) = trim_registry_exe_path(&value) {
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("QQ.exe"))
                {
                    return Some(path);
                }

                if let Some(parent) = path.parent() {
                    let qq_path = parent.join("QQ.exe");
                    if qq_path.exists() {
                        return Some(qq_path);
                    }
                }
            }
        }
    }

    None
}

fn explicit_qq_path_from_args() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--qq" || arg == "--qq-path" {
            if let Some(path) = args.next() {
                let path = PathBuf::from(path);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn find_qq_path(launcher_dir: &Path) -> Option<PathBuf> {
    if let Some(path) = explicit_qq_path_from_args() {
        return Some(path);
    }

    let colocated = launcher_dir.join("QQ.exe");
    if colocated.exists() {
        return Some(colocated);
    }

    qq_from_registry()
}

unsafe fn inject_dll(process: HANDLE, dll_path: &Path) -> Result<(), String> {
    let dll_path_w = path_to_wide(dll_path);
    let dll_path_bytes = dll_path_w.len() * size_of::<u16>();

    let remote_buf = unsafe {
        VirtualAllocEx(
            process,
            null(),
            dll_path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buf.is_null() {
        return Err(last_error("VirtualAllocEx failed"));
    }

    let mut written = 0usize;
    let write_ok = unsafe {
        WriteProcessMemory(
            process,
            remote_buf,
            dll_path_w.as_ptr().cast::<c_void>(),
            dll_path_bytes,
            &mut written,
        )
    };
    if write_ok == 0 || written != dll_path_bytes {
        unsafe {
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return Err(last_error("WriteProcessMemory failed"));
    }

    let kernel32 = unsafe { GetModuleHandleW(wide_null("kernel32.dll").as_ptr()) };
    if kernel32.is_null() {
        unsafe {
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return Err(last_error("GetModuleHandleW(kernel32.dll) failed"));
    }

    let load_library = unsafe { GetProcAddress(kernel32, c"LoadLibraryW".as_ptr().cast()) };
    let Some(load_library) = load_library else {
        unsafe {
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return Err(last_error("GetProcAddress(LoadLibraryW) failed"));
    };

    let start: LPTHREAD_START_ROUTINE = unsafe { transmute(load_library) };
    let thread =
        unsafe { CreateRemoteThread(process, null(), 0, start, remote_buf, 0, null_mut()) };
    if thread.is_null() {
        unsafe {
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return Err(last_error("CreateRemoteThread failed"));
    }

    unsafe {
        WaitForSingleObject(thread, INFINITE);
    }

    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeThread(thread, &mut exit_code);
        close_handle(thread);
        VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
    }

    if exit_code == 0 {
        return Err("LoadLibraryW failed in remote process".to_string());
    }

    Ok(())
}

unsafe fn run() -> Result<(), String> {
    let launcher_dir = exe_dir()?;
    let qq_path = find_qq_path(&launcher_dir)
        .ok_or_else(|| "QQ.exe not found in launcher directory or registry".to_string())?;
    let dll_path = launcher_dir.join("NapCatWinBootHook.dll");

    if !qq_path.exists() {
        return Err(format!("QQ.exe not found: {}", qq_path.display()));
    }
    if !dll_path.exists() {
        return Err(format!(
            "NapCatWinBootHook.dll not found: {}",
            dll_path.display()
        ));
    }

    let qq_path_w = path_to_wide(&qq_path);
    let qq_dir = qq_path
        .parent()
        .ok_or_else(|| format!("cannot get QQ.exe parent directory: {}", qq_path.display()))?;
    let qq_dir_w = path_to_wide(qq_dir);

    let mut startup_info: STARTUPINFOW = unsafe { zeroed() };
    startup_info.cb = size_of::<STARTUPINFOW>() as u32;

    let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };
    let create_ok = unsafe {
        CreateProcessW(
            qq_path_w.as_ptr(),
            null_mut(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            null(),
            qq_dir_w.as_ptr(),
            &startup_info,
            &mut process_info,
        )
    };

    if create_ok == 0 {
        return Err(last_error("CreateProcessW(QQ.exe) failed"));
    }

    let inject_result = unsafe { inject_dll(process_info.hProcess, &dll_path) };
    if let Err(err) = inject_result {
        unsafe {
            TerminateProcess(process_info.hProcess, 1);
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
        }
        return Err(err);
    }

    unsafe {
        ResumeThread(process_info.hThread);
        close_handle(process_info.hThread);
        close_handle(process_info.hProcess);
    }

    Ok(())
}

fn main() {
    if let Err(err) = unsafe { run() } {
        show_error(&err);
    }
}
