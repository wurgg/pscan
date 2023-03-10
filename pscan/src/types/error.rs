#[derive(Debug)]
pub struct ScanError {
    pub error: String
}

impl ScanError {
    pub fn new(error: String) -> Self{
        Self { error }
    }
}