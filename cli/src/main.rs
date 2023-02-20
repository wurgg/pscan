fn main() {
    println!("Scan started...");
    let result = pscan::new(String::from("Notepad.exe"), String::from("patty"), String::from("masky"))
    .module(String::from("Notepad.exe"))
    .scan();
    println!("\n\t\t[Result]\n\tprocess: {}\n\tpid: {}\n\tmodule: {}\n\tpattern: {}\n\tmask: {}\n\tfound: {}\n\tfound_at: {}",
        result.process_name,
        result.pid,
        result.module.unwrap_or(String::from("<not specified>")),
        result.pattern,
        result.mask,
        result.pattern_found,
        result.pattern_found_at);
        println!("\n");
}
