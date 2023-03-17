use crate::Target;
use crate::process::get_handle;
use algo1::Algo1;
use bruteforce::Bruteforce;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::VirtualQueryEx;
use core::ffi::c_void;
use std::mem;

pub mod algo1;
pub mod bruteforce;

use crate::types::pattern::*;
use crate::types::scan_method::Method;
use crate::types::scan_result::ScanResult;
use crate::types::error::ScanError;





// All scanners must impl a scan function and a method to identify the scan method being used
pub trait Scanner {
    fn run(&self, value: [u8; 4096], pattern: &Pattern, chunk: &usize);
}

fn init_scanner(method: &Method) -> Box<dyn Scanner>{
    match method {
        Method::Algo1 => Box::new(Algo1),
        _ => Box::new(Bruteforce),
    }
}


pub fn start(target: Target) -> Result<ScanResult, ScanError>{
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
        //println!("\n[{}] current_chunk: {:02X?}\n", counter, current_chunk);
         // [2] Virtual protect ex
        unsafe { VirtualProtectEx(HANDLE, start_address, mbi.RegionSize, PAGE_EXECUTE_READWRITE, ptr_vprotect);}
        // [3] Read process memory

        if unsafe { ReadProcessMemory(HANDLE, current_chunk as *mut c_void, bytes_buffer.as_mut_ptr().cast(), mbi.RegionSize, Some(&mut number_of_bytes_read)) } == false{
        println!("Failed to RPM. Last OS error: {:?}\n", unsafe{ GetLastError()});
        }
        // [4] Virtual protext ex (restore)
        //println!("bytes: {:02X?}", bytes_buffer);
        unsafe { VirtualProtectEx(HANDLE, start_address, mbi.RegionSize, vprotect, ptr_vprotect);}
        scanner.run(bytes_buffer, &scan_result.pattern, &current_chunk);
        current_chunk += mbi.RegionSize;
    }
    println!("{} iterations completed. loop done.", counter);


    unsafe { CloseHandle(HANDLE); }
    println!("Last OS error: {:?}\n", unsafe{ GetLastError()});
    Ok(scan_result)
}




