fn main() {
    println!("Hello, world!");
    let result = pscan::new(String::from("Notepad.exe"), String::from("patty"), String::from("masky"))
    .scan();

    println!("\nResult:\n\nprocess: {}\nmodule: {:?}\npid: {}\npattern: {}\nmask: {}\nfound: {}\nfound_at: {}\n",
        result.process_name,
        result.module,
        result.pid,
        result.pattern,
        result.mask,
        result.found,
        result.found_at);
    println!("Goodbye, world!");
}
