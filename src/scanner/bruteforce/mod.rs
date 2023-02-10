use crate::scanner::*;



pub struct Bruteforce;



impl Scanner for Bruteforce{
    fn run(&self, value: &str) -> () {
        print!("hello from bruty [{}]\n", value)
    }
}