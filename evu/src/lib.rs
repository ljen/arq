#![allow(dead_code)] // TODO(nlopes): remove at the end

extern crate arq;
extern crate clap;
extern crate rpassword;
extern crate chrono; // Added for arq7_handler
extern crate filetime; // Added for arq7_handler

pub mod cli;
pub mod computers;
pub mod error;
pub mod folders;
pub mod tree;
pub mod recovery;
pub mod arq7_handler; // Added new module
pub mod utils;
