# pscan
Just a fun project I used to learn Rust. This project will scan a process & sub module for a matching array of bytes. Wild cards are supported. Common use cases would be game hacking, botting, finding memory signatures, etc.

This could be improved to be more idiomatic Rust, but it was a fun learning experience.

example usage:

    let res = pscan::new(String::from("Notepad.exe"), String::from("94 28 ? ?"))
    .module(String::from("Notepad.exe"))
    .scan();
