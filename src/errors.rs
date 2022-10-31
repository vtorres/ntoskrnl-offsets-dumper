use std::fmt::{ Formatter, Display, Result };

#[derive(Debug)]
pub enum OffsetDumperError {
    Radare2NotFoundError,
    Radare2VersionError,
    NtoskrnlNotValidError,
    NtoskrnlVersionNotFoundError,
    NtoskrnlDownloadingPdbError,
    NtoskrnlDumpingOffsetsError,
}

impl Display for OffsetDumperError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            OffsetDumperError::Radare2NotFoundError =>
                write!(
                    f,
                    "Radare2 not found! Please check your installation path. Dependencies: Radare2 >= 5.0.0"
                ),
            OffsetDumperError::Radare2VersionError =>
                write!(f, "To work properly, please use Radare2 version >= 5.0.0"),
            OffsetDumperError::NtoskrnlNotValidError =>
                write!(f, "The configured ntoskrnl.exe does not exists or is not a file."),
            OffsetDumperError::NtoskrnlVersionNotFoundError =>
                write!(
                    f,
                    "Radare2 could not find ntoskrnl.exe file version. Please double-check your ntoskrnl file."
                ),
            OffsetDumperError::NtoskrnlDownloadingPdbError =>
                write!(
                    f,
                    "Radare2 could not download PDF files for this file version. Please double-check your ntoskrnl file."
                ),
            OffsetDumperError::NtoskrnlDumpingOffsetsError =>
                write!(f, "Radare2 got an error while dumping ntoskrnl.exe. Sorry!"),
        }
    }
}