#[cfg(test)]
use std::io::{Cursor, Read};

#[cfg(test)]
pub struct NonSeekReader {
    pub inner: Cursor<Vec<u8>>,
}

#[cfg(test)]
impl Read for NonSeekReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(test)]
pub fn arq_string(value: &str) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    bytes
}
