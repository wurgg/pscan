use std::str::FromStr;

use crate::types::scan_method::Method;
use crate::types::pattern::Pattern;
use crate::types::error::ScanError;
use crate::Target;
use crate::process;







pub struct ScanResult {
    pub process_name: String,
    pub module: Option<String>,
    pub pid: u32,
    pub method: Method,
    pub pattern: Pattern,
    pub pattern_found: bool,
    pub pattern_found_at: usize,
    pub size: usize,
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
            pattern: Pattern::from_str(&target.pattern)?,
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
            return Err(ScanError::new(String::from("Could not find the process with the specified name.")) );
         }
        println!("pid g2g");
        match process::get_scan_range(result) {
            Ok(res) => return Ok(res), 
            Err(e) => return Err(ScanError::new(String::from(e.error))),
        }
    }


}
