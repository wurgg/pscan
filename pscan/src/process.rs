use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32, MODULEENTRY32, TH32CS_SNAPPROCESS, Process32Next, Module32Next, TH32CS_SNAPMODULE};
use windows::Win32::System::Threading::{PROCESS_ALL_ACCESS, OpenProcess};
use crate::types::scan_result::ScanResult;


// Errors
pub struct ProcessError {
    pub error: String,
}


pub fn get_proc_id(proc_name: String) -> u32 {
    unsafe {
    let mut proc_id: u32 = 0;

    // Create snap of all processes
    let h_snap = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
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
                println!("[{}] found with process id of [{}]", proc_name, proc_id);
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

pub fn get_module(pid: &u32, module_name: &String) -> Result<windows::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32, ProcessError> {
    unsafe {
        // Create snap of a specific process specified by pid argument
        let h_snap = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE,
            *pid,
        );

        // Make sure the snap is valid
        let h_snap = match h_snap {
            Ok(t) => t,
            Err(e) => panic!("error {}", e),
        };

        // Setup a module entry we can use to reference each moduleentry32 when we loop the snapshot. Gets assigned a new one each loop
        let mut current_me32: MODULEENTRY32 = MODULEENTRY32 {
            ..MODULEENTRY32::default()
        };

        // Setup a second module entry. This one will hold the final result if a match is found.
        let mut output_me32 = MODULEENTRY32 {
            ..MODULEENTRY32::default()
        };

        // Setup the size as required by winapi
        current_me32.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        // set up pointer to use in Module32First (winapi)
        let entry_ptr = &mut current_me32 as *mut MODULEENTRY32;
    
    // Did we successfully get the first process?
    if windows::Win32::System::Diagnostics::ToolHelp::Module32First(h_snap, entry_ptr).as_bool() {
        // We successfully got the first process from the snapshot, lets loop over them
        loop {
            // format process name returned by processentry32.szExeFile string for comparison
            let module_string: String = current_me32.szModule.iter().take_while(|e| e.0 != 0).map(|e| e.0 as char).collect();
            // Do we have a match?
            if module_string.eq(module_name) {
                output_me32 = current_me32.clone();
                println!("Module [{}] found within process with base address of [{:?}]", module_name, current_me32.modBaseAddr);
                break;
            }

            // as long as there is another module in the snapshot...
            if !Module32Next(h_snap, entry_ptr).as_bool() {
                break;
            }
        }
    }
    // close handle as we dont need it any longer
    CloseHandle(h_snap);

    // Did we get a match?
    if output_me32.modBaseSize == 0 {
        // No match
        return Err(ProcessError { error: String::from("Failed to get module.") });
    }
    // Match found
    return Ok(output_me32)
    }
}

pub fn get_handle(pid: u32) -> Result<HANDLE, windows::core::Error> {
    unsafe {
        return OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    }
}

pub fn get_scan_range(result: ScanResult) -> Result<ScanResult, ProcessError> {
    // Is there a module provided?
    let mut res = result;
    if res.module.is_some() {
        // Yes, let's unwrap
        let mod_name = res.module.clone().unwrap();
        println!("Looking for module [{}] within process [{} ({})]", mod_name, res.process_name, res.pid);
        // Get module
        match get_module(&res.pid, &mod_name) {
            Ok(me32) => {
            // Get Scan range (addresses)
            println!("base:  {:?}", me32.modBaseAddr);
            res.start_address = me32.modBaseAddr as usize;
            println!("size: {}",   me32.modBaseSize, );
            res.size = me32.modBaseSize as usize;
            println!("base + size: {:?}", unsafe{ me32.modBaseAddr.offset(me32.modBaseSize.try_into().unwrap())});
            res.end_address = unsafe { me32.modBaseAddr.offset(me32.modBaseSize.try_into().unwrap())}  as usize;
            },
            Err(e) => {
                println!("Scan failed: {}", e.error);    
                return Err(e);
            },
        }
    }
    else {
        print!("No module was specified...\n");
        // figure out entire proc size?
    }
        Ok(res)
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

