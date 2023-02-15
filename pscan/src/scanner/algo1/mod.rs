use crate::scanner::*;




pub struct Algo1;

impl Scanner for Algo1{
    fn run(&self, value: &str) -> () {
        print!("hello from algo1 [{}]\n", value)
    }
}