// expose functions to perform a scan etc.
mod scanner;
mod process;
pub mod scan_type;
use scan_type::Method;
use scanner::ScanError;


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
    pub fn scan(self) -> Result<scanner::ScanResult, ScanError> {
        scanner::start(self)
    }

    pub fn module(mut self, module_name: String) -> Target {
        self.module = Some(module_name);
        self
    }
}


