use crate::scanner::*;




pub struct Algo1;

impl Scanner for Algo1{
    fn run(&self, value: &str) -> () {
        print!("[algo1]: [{}]\n", value)
    }
}