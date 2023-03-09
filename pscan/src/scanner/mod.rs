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
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::VirtualQueryEx;
use core::ffi::c_void;
use std::mem;
use std::str::FromStr;
use std::fmt;
mod algo1;
mod bruteforce;



#[derive(Debug)]
pub struct ScanError {
    pub error: String
}

impl ScanError {
    pub fn new(error: String) -> Self{
        Self { error }
    }
}

pub enum PatternByte {
    Byte(u8),
    Any,
}

impl FromStr for PatternByte {
    type Err = ScanError;
    /// Create an instance of [`PatternByte`] from a string.
    ///
    /// This string should either be a hexadecimal byte, or a "?". Will return an error if the
    /// string is not a "?", or it cannot be converted into an 8-bit integer when interpreted as
    /// hexadecimal.
    fn from_str(s: &str) -> Result<Self, ScanError> {
        if s == "?" {
            Ok(Self::Any)
        } else {
            let n = match u8::from_str_radix(s, 16) {
                Ok(n) => Ok(n),
                Err(e) => Err(ScanError::new(format!("from_str_radix failed: {}", e))),
            }?;

            Ok(Self::Byte(n))
        }
    }
}

impl PartialEq<u8> for PatternByte {
    fn eq(&self, other: &u8) -> bool {
        match self {
            PatternByte::Any => true,
            PatternByte::Byte(b) => b == other,
        }
    }
}

impl fmt::Display for PatternByte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PatternByte::Any => write!(f, "?"),
            PatternByte::Byte(b) => write!(f, "{}", b),
        }
    }
}

pub struct Pattern {
    bytes: Vec<PatternByte>,
}

impl Pattern {
    pub fn new(bytes: Vec<PatternByte>) -> Self {
        Self { bytes }
    }

    pub fn len(&self)-> usize{
        self.bytes.len()
    }

    pub fn to_str(&self) -> String {
        let mut output = Vec::new();
        for i in 0..self.len(){
            output.push(self.bytes[i].to_string());
        }
        output.into_iter().collect()
    }
}

impl FromStr for Pattern {
    type Err = ScanError;

    fn from_str(s: &str) -> Result<Self, ScanError> {
        let mut bytes = Vec::new();

        for segment in s.split_ascii_whitespace() {
            bytes.push(PatternByte::from_str(segment)?);
        }

        Ok(Self::new(bytes))
    }
}




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
        match result.get_scan_range() {
            Ok(res) => return Ok(res), 
            Err(e) => return Err(ScanError::new(String::from(e.error))),
        }
        println!("scan range g2g");
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
            self.size = me32.modBaseSize as usize;
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
    fn run(&self, value: [u8; 4096], pattern: &Pattern);
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
    let start_address = scan_result.start_address as *const c_void;
    let mut vprotect = PAGE_PROTECTION_FLAGS::default();
    let ptr_vprotect = &mut vprotect as *mut PAGE_PROTECTION_FLAGS;
    let mut bytes_buffer: [u8; 4096] = [0; 4096];
    let mut number_of_bytes_read: usize = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();

    // populate our mbi
    unsafe{ VirtualQueryEx(HANDLE, Some(start_address), &mut mbi as *mut MEMORY_BASIC_INFORMATION, mem::size_of::<MEMORY_BASIC_INFORMATION>()) };
    println!("mbi region size: {} / 0x{:X}", mbi.RegionSize, mbi.RegionSize);
   
    

    let mut current_chunk = scan_result.start_address;
    dbg!(scan_result.start_address);
    dbg!(scan_result.start_address + mbi.RegionSize);
    dbg!(scan_result.size);

    // init scanner
    let scanner = init_scanner(&scan_result.method);


    // loop memory chunks
    let mut counter = 0;
    while current_chunk < scan_result.start_address + scan_result.size {
        counter += 1;
        println!("\n[{}] current_chunk: {:02X?}\n", counter, current_chunk);
         // [2] Virtual protect ex
        unsafe { VirtualProtectEx(HANDLE, start_address, mbi.RegionSize, PAGE_EXECUTE_READWRITE, ptr_vprotect);}
        // [3] Read process memory

        if unsafe { ReadProcessMemory(HANDLE, current_chunk as *mut c_void, bytes_buffer.as_mut_ptr().cast(), mbi.RegionSize, Some(&mut number_of_bytes_read)) } == false{
        println!("Failed to RPM. Last OS error: {:?}\n", unsafe{ GetLastError()});
        }
        // [4] Virtual protext ex (restore)
        //println!("bytes: {:02X?}", bytes_buffer);
        unsafe { VirtualProtectEx(HANDLE, start_address, mbi.RegionSize, vprotect, ptr_vprotect);}
        scanner.run(bytes_buffer, &scan_result.pattern);
        current_chunk += mbi.RegionSize;
    }
    println!("loop done.");


    unsafe { CloseHandle(HANDLE); }
    println!("Last OS error: {:?}\n", unsafe{ GetLastError()});
    Ok(scan_result)
}




