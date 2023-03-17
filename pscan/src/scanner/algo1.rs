use crate::scanner::*;
use crate::types::pattern::*;




pub struct Algo1;

impl Scanner for Algo1{
    fn run(&self, value: [u8; 4096], pattern: &Pattern, chunk: &usize) -> () {

        print!("{:02X?} ", value);
        print!("{:02X?} ", pattern.bytes.len());
        print!("{:02X?} ", chunk);
        unimplemented!("algo1 is not yet implemented...");
        /*
        for i in 0..value.len(){
            // your code here
        }
        */
    }
}