use crate::Target;
use crate::process;
use crate::process::get_handle;
use crate::scan_type::*;
use algo1::Algo1;
use bruteforce::Bruteforce;

mod algo1;
mod bruteforce;

pub struct ScanResult{
    pub process_name: String,
    pub module: Option<String>,
    pub pid: u32,
    pub pattern: String,
    pub mask: String,
    pub found: bool,
    pub found_at: String,
    // stats...
}

impl ScanResult{
    pub fn new(process_name: String, module: Option<String>, pattern: String, mask: String) -> ScanResult{
        ScanResult {
            process_name: process_name.clone(),
            module,
            pid: process::get_proc_id(process_name),
            pattern,
            mask,
            found: false,
            found_at: String::from("0xNOTFOUND"),
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
    let mut scan_result = ScanResult::new(target.process_name,target.module, target.pattern, target.mask);

    // get HANDLE
    let HANDLE = get_handle(scan_result.pid);

    // construct data chunks
    let memory_chunks = vec!["1", "2", "3"];

    let scanner = init_scanner(&target.method);

    for chunk in &memory_chunks{
        scanner.run(&chunk);
    }
    scan_result
}




