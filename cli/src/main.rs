use std::io;
fn main() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    println!("You pressed: {}", input);

    println!("Scan started...");
    if let Ok(result) = pscan::new(String::from("Notepad.exe"), String::from("patty"), String::from("masky"))
    .module(String::from("Notepad.exe"))
    .scan() {
        println!("\n\t\t[Result]\n\tprocess: {}\n\tpid: {}\n\tmodule: {}\n\tpattern: {}\n\tmask: {}\n\tfound: {}\n\tfound_at: {}\n
        \tsize: {}\n \tstart_address: {:X}\n \tend_address: {:X}\n",
            result.process_name,
            result.pid,
            result.module.unwrap_or(String::from("<not specified>")),
            result.pattern,
            result.mask,
            result.pattern_found,
            result.pattern_found_at,
            result.size,
            result.start_address,
            result.end_address);
            println!("\n");
    }
}
