#![feature(pointer_byte_offsets)]
use crate::Target;
use crate::process;
use crate::process::ProcessError;
use crate::process::get_handle;
use crate::process::get_module;
use crate::scan_type::*;
use algo1::Algo1;
use bruteforce::Bruteforce;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
use windows::Win32::System::Memory::VirtualProtectEx;
use core::ffi::c_void;

mod algo1;
mod bruteforce;

#[derive(Debug)]
pub struct ScanError {
    pub Error: String
}

pub struct ScanResult {
    pub process_name: String,
    pub module: Option<String>,
    pub pid: u32,
    pub method: Method,
    pub pattern: String,
    pub mask: String,
    pub pattern_found: bool,
    pub pattern_found_at: usize,
    pub size: u32,
    pub start_address: usize,
    pub end_address: usize,
    pub bytes_scanned: u32,
    // stats...
}

impl ScanResult{
    pub fn new(target: Target) -> Result<ScanResult, ScanError>{
       let result = ScanResult {
            process_name: target.process_name.clone(),
            module: target.module,
            method: target.method,
            pid: process::get_proc_id(target.process_name),
            pattern: target.pattern,
            mask: target.mask,
            pattern_found: false,
            pattern_found_at: 0,
            size: 0,
            start_address: 0,
            end_address: 0,
            bytes_scanned: 0,
        };
            // process not found, just end the scan
        if result.pid == 0 {
            println!("Scan failed: Could not find process by the name of: {}", result.process_name);
            return Err( ScanError { Error: String::from("Could not find the process with the specified name.") });
         }
        
        match result.get_scan_range() {
            Ok(res) => return Ok(res), 
            Err(e) => return Err(ScanError { Error: String::from(e.error) }),
        }
    }

    fn get_scan_range(mut self) -> Result<ScanResult, ProcessError> {
    // Is there a module provided?
    if self.module.is_some() {
        // Yes, let's unwrap
        let mod_name = self.module.clone().unwrap();
        println!("Looking for module [{}] within process [{} ({})]", mod_name, self.process_name, self.pid);
        // Get module
        match get_module(&self.pid, &mod_name) {
            Ok(me32) => {
            // Get Scan range (addresses)
            println!("base:  {:?}", me32.modBaseAddr);
            self.start_address = me32.modBaseAddr as usize;
            println!("size: {}",   me32.modBaseSize, );
            self.size = me32.modBaseSize;
            println!("base + size: {:?}", unsafe{ me32.modBaseAddr.offset(me32.modBaseSize.try_into().unwrap())});
            self.end_address = unsafe { me32.modBaseAddr.offset(me32.modBaseSize.try_into().unwrap())}  as usize;
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
        Ok(self)
    }
}

// All scanners must impl a scan function and a method to identify the scan method being used
pub trait Scanner {
    fn run(&self, value: &str);
}

fn init_scanner(method: &Method) -> Box<dyn Scanner>{
    match method {
        Method::Algo1 => Box::new(Algo1),
        _ => Box::new(Bruteforce),
    }
}


pub  fn start(target: Target) -> Result<ScanResult, ScanError>{
    // Init scan result
    let new_scan_result = ScanResult::new(target);

    // Something went wrong with initializing the scan result
    if let Err(e) = new_scan_result {
        return Err(e);
    };

    let scan_result = new_scan_result.unwrap();
    // [1] get HANDLE
    let HANDLE = match get_handle(scan_result.pid) {
        Ok(handle) => handle,
        Err(e) => panic!("Failed to get handle to the process!\n {}", e.message()),
    };
    // setup re-used vars
    //let HANDLE = H.unwrap_or_default();
    let start_address = scan_result.start_address as *const c_void ;
    dbg!(start_address);
    let size = usize::try_from(scan_result.size).unwrap();
    let mut vprotect = PAGE_PROTECTION_FLAGS::default();
    let ptr_vprotect = &mut vprotect as *mut PAGE_PROTECTION_FLAGS;
    let mut bytes_buffer: [u8; 64] = [0; 64];
    let mut number_of_bytes_read: usize = 0;
    // [2] Virtual protect ex
    println!("vprotect 1");
    //unsafe { VirtualProtectEx(HANDLE, start_address, size, PAGE_EXECUTE_READWRITE, ptr_vprotect);}
    // [3] Read process memory
    println!("vprotect 2");

    if unsafe { ReadProcessMemory(HANDLE, start_address, bytes_buffer.as_mut_ptr().cast(), 64, Some(&mut number_of_bytes_read)) } == false{
        println!("Failed to RPM. Last OS error: {:?}\n", unsafe{ GetLastError()});
    }
    // [4] Virtual protext ex (restore)
    println!("vprotect 3");
    println!("bytes: {:X?}", bytes_buffer);

    //unsafe { VirtualProtectEx(HANDLE, start_address, size, vprotect, ptr_vprotect);}
    println!("vprotect 4");
    
    //println!("bytes read: {:?}\n", number_of_bytes_read.unwrap());
    // construct data chunks
    let memory_chunks = vec!["1", "2", "3"];

    // init scanner
    let scanner = init_scanner(&scan_result.method);

    // scan chunks
    for chunk in &memory_chunks{
        scanner.run(&chunk);
    }
    unsafe { CloseHandle(HANDLE); }
    println!("Last OS error: {:?}\n", unsafe{ GetLastError()});
    Ok(scan_result)
}




