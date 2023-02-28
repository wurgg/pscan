#![feature(pointer_byte_offsets)]
use crate::Target;
use crate::process;
use crate::process::get_handle;
use crate::process::get_module;
use crate::scan_type::*;
use algo1::Algo1;
use bruteforce::Bruteforce;
use windows::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32;

mod algo1;
mod bruteforce;

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
    pub fn new(target: Target) -> ScanResult{
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
            return result;
         }
        
        return result.get_scan_range();
    }

    fn get_scan_range(mut self) -> ScanResult {
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
                return self
            },
        }
    }
    else {
        print!("No module was specified...\n");
    }
        self
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


pub  fn start(target: Target) -> ScanResult{
    // Init scan result
    let mut scan_result = ScanResult::new(target);

    // [1] get HANDLE
    let HANDLE = get_handle(scan_result.pid);

    // [2] Virtual protect ex
    // [3] Read process memory
    // [4] Virtual protext ex (restore)

    // construct data chunks
    let memory_chunks = vec!["1", "2", "3"];

    // init scanner
    let scanner = init_scanner(&scan_result.method);

    // scan chunks
    for chunk in &memory_chunks{
        scanner.run(&chunk);
    }
    scan_result
}




