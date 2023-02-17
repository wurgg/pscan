use crate::Target;
use crate::process;
use crate::process::get_handle;
use crate::process::get_module;
use crate::scan_type::*;
use algo1::Algo1;
use bruteforce::Bruteforce;

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
    pub start_at: String,
    pub end_at: String,
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
            start_at: String::from("0x0"),
            end_at: String::from("0xFFFFFFFFF"),
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
        println!("ERROR! Could not find process by the name of: {}", scan_result.process_name);
        return scan_result;
    }

    // Is there a module provided?
    if scan_result.module.is_some() {
        // Yes, let's unwrap
        let mod_name = scan_result.module.clone().unwrap();
        println!("Looking for module [{}]", mod_name);
        // Get module
        let me32 = get_module(&scan_result.pid, &mod_name);
        // Get Scan range (addresses)
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




