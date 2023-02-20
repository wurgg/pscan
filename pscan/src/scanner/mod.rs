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
    pub pattern_found_at: String,
    pub start_address: u32,
    pub end_address: String,
    pub bytes_scanned: u32,
    // stats...
}

impl ScanResult{
    pub fn new(target: Target) -> ScanResult{
        ScanResult {
            process_name: target.process_name.clone(),
            module: target.module,
            method: target.method,
            pid: process::get_proc_id(target.process_name),
            pattern: target.pattern,
            mask: target.mask,
            pattern_found: false,
            pattern_found_at: String::from("0xNOTFOUND"),
            start_address: 0,
            end_address: String::from("0xFFFFFFFFF"),
            bytes_scanned: 0,
        }
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

    // process not found, just end the scan
    if scan_result.pid == 0 {
        println!("Scan failed: Could not find process by the name of: {}", scan_result.process_name);
        return scan_result;
    }

    // Is there a module provided?
    if scan_result.module.is_some() {
        // Yes, let's unwrap
        let mod_name = scan_result.module.clone().unwrap();
        println!("Looking for module [{}] within process [{} ({})]", mod_name, scan_result.process_name, scan_result.pid);
        // Get module
        match get_module(&scan_result.pid, &mod_name) {
            Ok(me32) => {
            // Get Scan range (addresses)
            println!("base:  {:?}", me32.modBaseAddr);
            println!("size: {}",   me32.modBaseSize, );
            println!("base + size: {:?}", unsafe{ me32.modBaseAddr.offset(me32.modBaseSize.try_into().unwrap())});
            },
            Err(e) => {
                println!("Scan failed: {}", e.error);    
                return scan_result
            },
        }
    }
    else {
        print!("No module was specified...\n");
    }

    // get HANDLE
    let HANDLE = get_handle(scan_result.pid);

    // RPM

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




