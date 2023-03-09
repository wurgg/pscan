use crate::scanner::*;




pub struct Algo1;

impl Scanner for Algo1{
    fn run(&self, value: [u8; 4096], pattern: &Pattern, chunk: &usize) -> () {
        print!("{:02X?} ", value);

        for i in 0..value.len(){

        }
    }
}