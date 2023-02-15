// expose functions to perform a scan etc.
mod scanner;
mod process;
pub mod scan_type;
use scan_type::Method;


pub fn new(process_name: String, pattern: String, mask: String) -> Target {
    Target{
        process_name,
        module: None,
        method: Method::Bruteforce,
        pattern,
        mask,
    }
}

pub struct Target {
   pub process_name: String,
   pub method: Method,
   pub module: Option<String>,
   pub pattern: String,
   pub mask: String,
}

impl Target {
    pub fn scan(self) -> scanner::ScanResult {
        scanner::start(self)
    }

    pub fn module(mut self, module_name: String) -> Target {
        self.module = Some(module_name);
        self
    }
}


