use crate::scanner::*;



pub struct Bruteforce;



impl Scanner for Bruteforce{
    fn run(&self, value: [u8; 4096]) -> () {
        print!("{:02X?} ", value)
    }
}