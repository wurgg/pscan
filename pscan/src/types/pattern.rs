use std::str::FromStr;
use std::fmt;
use crate::types::error::ScanError;

pub enum PatternByte {
    Byte(u8),
    Any,
}



impl FromStr for Pattern {
    type Err = ScanError;

    fn from_str(s: &str) -> Result<Self, ScanError> {
        let mut bytes = Vec::new();

        for segment in s.split_ascii_whitespace() {
            bytes.push(PatternByte::from_str(segment)?);
        }

        Ok(Self::new(bytes))
    }
}

impl FromStr for PatternByte {
    type Err = ScanError;
    /// Create an instance of [`PatternByte`] from a string.
    ///
    /// This string should either be a hexadecimal byte, or a "?". Will return an error if the
    /// string is not a "?", or it cannot be converted into an 8-bit integer when interpreted as
    /// hexadecimal.
    fn from_str(s: &str) -> Result<Self, ScanError> {
        if s == "?" {
            Ok(Self::Any)
        } else {
            let n = match u8::from_str_radix(s, 16) {
                Ok(n) => Ok(n),
                Err(e) => Err(ScanError::new(format!("from_str_radix failed: {}", e))),
            }?;

            Ok(Self::Byte(n))
        }
    }
}

impl PartialEq<u8> for PatternByte {
    fn eq(&self, other: &u8) -> bool {
        match self {
            PatternByte::Any => true,
            PatternByte::Byte(b) => b == other,
        }
    }
}

impl fmt::Display for PatternByte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PatternByte::Any => write!(f, "?? "),
            PatternByte::Byte(b) => write!(f, "{:2X} ", b),
        }
    }
}

pub struct Pattern {
    pub bytes: Vec<PatternByte>,
}

impl Pattern {
    pub fn new(bytes: Vec<PatternByte>) -> Self {
        Self { bytes }
    }

    pub fn len(&self)-> usize{
        self.bytes.len()
    }

    pub fn to_str(&self) -> String {
        let mut output = Vec::new();
        for i in 0..self.len(){
            output.push(self.bytes[i].to_string());
        }
        output.into_iter().collect()
    }
}

