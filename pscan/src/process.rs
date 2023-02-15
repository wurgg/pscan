use windows::Win32::Foundation::{CHAR, CloseHandle, GetLastError};
use windows::Win32::Foundation::{HANDLE, BOOL, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32, MODULEENTRY32, TH32CS_SNAPPROCESS, Process32First, Process32Next, Module32First, Module32Next, CreateToolhelp32Snapshot, CREATE_TOOLHELP_SNAPSHOT_FLAGS, Toolhelp32ReadProcessMemory};
use windows::Win32::System::Threading::{PROCESS_ALL_ACCESS, OpenProcess};
use std::ffi::c_void;


pub fn get_proc_id(proc_name: String) -> u32 {
    unsafe {
    let mut proc_id: u32 = 0;

    // Create snap of all processes
    let mut h_snap = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0,
    );

    // Make sure the snap is valid
    let h_snap = match h_snap {
        Ok(t) => t,
        Err(e) => panic!("error {}", e),
    };
    
    // Set up our varible to hold data returned by toolhelp when a match is found
    let mut proc_entry: PROCESSENTRY32 = PROCESSENTRY32 {
        ..PROCESSENTRY32::default()
    };
    
    // set size of type in dwSize field
    proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    // set up pointer to use in Process32First (winapi)
    let entry_ptr = &mut proc_entry as *mut PROCESSENTRY32;
    
    // Did we successfully get the first process?
    if windows::Win32::System::Diagnostics::ToolHelp::Process32First(h_snap, entry_ptr).as_bool() {
        // We successfully got the first process from the snapshot, lets loop over them
        loop {
            // format process name returned by processentry32.szExeFile string for comparison
            let proc_exe_string: String = proc_entry.szExeFile.iter().take_while(|e| e.0 != 0).map(|e| e.0 as char).collect();

            // Do we have a match?
            if proc_exe_string.eq(&proc_name) {
                proc_id = proc_entry.th32ProcessID;
                println!("\n[][][] WE HAVE A MATCH [][][]\n{} : {}\n=============================\n", proc_name, proc_exe_string);
                break;
            }

            // as long as there is another process in the snapshot...
            if !Process32Next(h_snap, entry_ptr).as_bool() {
                break;
            }
        }
    }
    CloseHandle(h_snap);
    return proc_id; 
}
}

pub fn get_module(pid: u32, module_name: String) -> windows::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32 {
    unsafe {
        // Create snap of a specific process specified by pid argument
        let mut h_snap = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS,
            pid,
        );

        // Make sure the snap is valid
        let h_snap = match h_snap {
            Ok(t) => t,
            Err(e) => panic!("error {}", e),
        };

        // Setup our var to hold the moduleentry32 if a match is made
        let mut me32: MODULEENTRY32 = MODULEENTRY32 {
            ..MODULEENTRY32::default()
        };

        // Setup the size as required by winapi
        me32.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        // set up pointer to use in Module32First (winapi)
    let entry_ptr = &mut me32 as *mut MODULEENTRY32;

    // Did we successfully get the first process?
    if windows::Win32::System::Diagnostics::ToolHelp::Module32First(h_snap, entry_ptr).as_bool() {
        // We successfully got the first process from the snapshot, lets loop over them
        loop {
            // format process name returned by processentry32.szExeFile string for comparison
            let module_string: String = me32.szModule.iter().take_while(|e| e.0 != 0).map(|e| e.0 as char).collect();

            // Do we have a match?
            if module_string.eq(&module_name) {
                println!("\n[][][] WE HAVE A MATCH [][][]\n{} : {}\n=============================\n", module_name, module_string);
                break;
            }

            // as long as there is another module in the snapshot...
            if !Module32Next(h_snap, entry_ptr).as_bool() {
                break;
            }
        }
    }
    CloseHandle(h_snap);

    return me32
    }
}

pub fn get_handle(pid: u32) -> Result<HANDLE, windows::core::Error> {
    unsafe {
        return OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    }
}

// Read process memory
// input: handle to process
/*
BOOL ReadProcessMemory(
    [in]  HANDLE  hProcess,
    [in]  LPCVOID lpBaseAddress,
    [out] LPVOID  lpBuffer,
    [in]  SIZE_T  nSize,
    [out] SIZE_T  *lpNumberOfBytesRead
  );*/
// output: bytes read
pub fn read_memory(handle: HANDLE, lpbaseaddress: *const c_void, lpbuffer: *mut c_void, nsize: usize, lpnumberofbytesread:Option<*mut usize>) -> () {
    unsafe {
        ReadProcessMemory(handle, lpbaseaddress, lpbuffer, nsize, lpnumberofbytesread);
    }
}

// Write to process memory
/*
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
 */
pub fn write_memory() -> () {
    todo!()
}