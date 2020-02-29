extern crate colored;
extern crate data_encoding;
extern crate ring;

use colored::*;
use data_encoding::HEXLOWER;
use ring::digest::{Context, Digest, SHA256};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process;

enum FileStatus {
    UNKNOWN,
    OK,
    REMOVED,
    MISMATCH,
    FAILED,
}

pub struct SHASumEntry {
    checksum: String,
    filepath: String,
    status: FileStatus,
}

impl fmt::Display for SHASumEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let colored_status = match self.status {
            FileStatus::OK => "OK".green().bold(),
            FileStatus::MISMATCH => "MISMATCH".red().bold(),
            FileStatus::REMOVED => "REMOVED".yellow().bold(),
            FileStatus::FAILED => "FAILED open or read".red().bold(),
            FileStatus::UNKNOWN => "UNKNOWN".white(),
        };
        write!(f, "{}: {}", self.filepath, colored_status)
    }
}

impl SHASumEntry {
    fn _calculate_checksum(&self) -> std::io::Result<Digest> {
        let input = File::open(&self.filepath)?;
        let mut context = Context::new(&SHA256);
        let mut buffer = [0; 4096];
        let mut reader = BufReader::new(input);

        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            context.update(&buffer[..count]);
        }

        Ok(context.finish())
    }

    fn check(&mut self) -> &FileStatus {
        if !Path::new(&self.filepath).exists() {
            self.status = FileStatus::REMOVED;
            return &self.status;
        }

        let checksum = match self._calculate_checksum() {
            Ok(checksum) => HEXLOWER.encode(checksum.as_ref()),
            Err(_) => {
                self.status = FileStatus::FAILED;
                return &self.status;
            }
        };
        if self.checksum != checksum {
            self.status = FileStatus::MISMATCH;
            return &self.status;
        }
        self.status = FileStatus::OK;
        return &self.status;
    }
}

struct SHASumFile {
    reader: BufReader<File>,
    num_ok: usize,
    num_removed: usize,
    num_mismatch: usize,
    num_failed: usize,
}


impl SHASumFile {
    fn new(path: &str) -> std::io::Result<SHASumFile> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(SHASumFile {
            reader: reader,
            num_ok: 0,
            num_removed: 0,
            num_mismatch: 0,
            num_failed: 0,
        })
    }

    fn print_summary(&self) -> i32 {
        if self.num_removed > 0 {
            if self.num_removed == 1 {
                eprintln!("WARNING: {} file has been removed", self.num_removed);
            } else {
                eprintln!("WARNING: {} files have been removed", self.num_removed);
            }
        }
        if self.num_mismatch > 0 {
            if self.num_mismatch == 1 {
                eprintln!("WARNING: {} checksum did NOT match", self.num_mismatch)
            } else {
                eprintln!("WARNING: {} checksums did NOT match", self.num_mismatch)
            }
        }
        if self.num_failed > 0 {
            if self.num_failed == 1 {
                eprintln!("WARNING: {} file could not be read", self.num_failed);
            } else {
                eprintln!("WARNING: {} files could not be read", self.num_failed);
            }
        }
        if self.num_removed == 0 && self.num_mismatch == 0 && self.num_failed == 0 {
            return 0;
        }
        return 1;
    }
}

impl Iterator for SHASumFile {
    type Item = SHASumEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        return match self.reader.read_line(&mut line) {
            Ok(_) => {
                let vec = line.trim().splitn(2, "  ").collect::<Vec<&str>>();
                if vec.len() != 2 {
                    return None;
                }
                let mut entry = SHASumEntry {
                    checksum: String::from(vec[0]),
                    filepath: String::from(vec[1]),
                    status: FileStatus::UNKNOWN,
                };
                match entry.check() {
                    FileStatus::OK => self.num_ok += 1,
                    FileStatus::REMOVED => self.num_removed += 1,
                    FileStatus::MISMATCH => self.num_mismatch += 1,
                    FileStatus::FAILED => self.num_failed += 1,
                    FileStatus::UNKNOWN => {}
                };
                Some(entry)
            }
            Err(_) => None,
        };
    }
}

fn main() {
    let path = "./sha256sum.txt";
    match &mut SHASumFile::new(path) {
        Ok(shasum_file) => {
            for entry in shasum_file.by_ref() {
                println!("{}", entry);
            }
            let exit_status = shasum_file.print_summary();
            process::exit(exit_status);
        }
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            process::exit(1);
        }
    };
}
