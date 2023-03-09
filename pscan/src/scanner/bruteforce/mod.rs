use crate::scanner::*;



pub struct Bruteforce;


// needs to be rustified lol
impl Scanner for Bruteforce{
    fn run(&self, value: [u8; 4096], pattern: &Pattern, chunk: &usize) -> () {
        for i in 0..value.len(){
            let mut found = true;
            for j in 0..pattern.len(){
                match pattern.bytes[j] {
                    PatternByte::Any => {},
                    PatternByte::Byte(b) => {
                        //println!("trying {:2X} : {:2X}\n", value[i+j], b);
                        if value[i+j] == b{
                            //println!("matched {:2X} : {:2X} @ {:2X}", value[i+j], b, chunk+i+j);
                        }
                        else {
                            found = false;
                            break;
                        }
                    }
                }
            }
            if found {
                println!("\n++++++++ pattern found at {:2X}\n", chunk+i);
            }
        }
    }
}