use std::{ io::stdin, process };

use crate::dumper::Dumper;

mod constants;
mod dumper;
mod errors;

pub type NtoskrnlOffsetsResult<A> = core::result::Result<A, errors::OffsetDumperError>;

fn main() -> NtoskrnlOffsetsResult<()> {
    fn print_error_and_exit(error: errors::OffsetDumperError, exit_code: i32) {
        if let Some(err) = error.into() {
            println!("Error: {err}");

            process::exit(exit_code);
        }
    }

    if !Dumper::is_r2_installed() {
        print_error_and_exit(errors::OffsetDumperError::Radare2NotFoundError, 127);
    }

    if !Dumper::is_r2_expected_version() {
        print_error_and_exit(errors::OffsetDumperError::Radare2VersionError, 1);
    }

    if !Dumper::is_ntoskrnl_valid() {
        print_error_and_exit(errors::OffsetDumperError::NtoskrnlNotValidError, 1);
    }

    match Dumper::download_ntoskrnl_pdb() {
        (true, message) => {
            println!("Downloading {}", message);
        }
        (false, _) => {
            print_error_and_exit(errors::OffsetDumperError::NtoskrnlDownloadingPdbError, 1);
        }
    }

    match Dumper::fetch_ntoskrnl_info() {
        Ok(version) => {
            println!("Ntoskrnl Version: {}", version);
        }
        Err(_) => {
            print_error_and_exit(errors::OffsetDumperError::NtoskrnlVersionNotFoundError, 1);
        }
    }

    match Dumper::dump_ntoskrnl_symbols() {
        Ok(offset_dump) => {
            println!("Offsets:");

            for item in offset_dump {
                println!("{item}");
            }
        }
        Err(_) => {
            print_error_and_exit(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError, 1);
        }
    }

    println!("Press ENTER to exit.");
    stdin().read_line(&mut String::new()).unwrap();

    Ok(())
}