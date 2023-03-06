use crate::scanner::*;




pub struct Algo1;

impl Scanner for Algo1{
    fn run(&self, value: [u8; 4096]) -> () {
        for v in 0..value.len() {
        print!("[algo1]: [{}]\n", v)
        }
    }
}