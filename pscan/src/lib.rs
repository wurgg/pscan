// expose functions to perform a scan etc.
mod types;
mod scanner;
mod process;

use types::scan_method::Method;
use types::error::ScanError;
use types::scan_result::ScanResult;

pub fn new(process_name: String, pattern: String) -> Target {
    Target{
        process_name,
        module: None,
        method: Method::Bruteforce,
        pattern,
    }
}

pub struct Target {
   pub process_name: String,
   pub method: Method,
   pub module: Option<String>,
   pub pattern: String,
}

impl Target {
    pub fn scan(self) -> Result<ScanResult, ScanError> {
        scanner::start(self)
    }

    pub fn module(mut self, module_name: String) -> Target {
        self.module = Some(module_name);
        self
    }
}


