use crate::scanner::*;



pub struct Bruteforce;



impl Scanner for Bruteforce{
    fn run(&self, value: &str) -> () {
        print!("[bruteforce]: [{}]\n", value)
    }
}