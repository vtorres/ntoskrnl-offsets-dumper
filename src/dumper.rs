use std::{ path::Path, fmt::{ Display, Formatter, Result }, process::{ Command, Output, Stdio } };

use regex::Regex;

use crate::{ errors, constants };

#[derive(Debug)]
pub struct OffsetsDump {
    pub kind: String,
    pub name: String,
    pub offset: String,
}

impl Display for OffsetsDump {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "[+] {} {} {}", self.kind, self.name, self.offset)
    }
}

pub struct Dumper();

impl Dumper {
    pub fn is_r2_installed() -> bool {
        Command::new(constants::RADARE_EXECUTABLE_NAME).stdout(Stdio::null()).spawn().is_ok()
    }

    pub fn is_r2_expected_version() -> bool {
        let radare_version: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-V")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(radare_version.stderr).unwrap();

        if !stderr.is_empty() {
            return false;
        }

        let radare_output_version = Regex::new(constants::SEMANTIC_VERSIONING_REGEX)
            .unwrap()
            .captures_iter(&String::from_utf8(radare_version.stdout).unwrap())
            .filter_map(|cap| {
                match (cap.get(1), cap.get(2), cap.get(3)) {
                    (Some(major), Some(minor), Some(patch)) =>
                        Some((
                            major.as_str().parse::<i8>().unwrap(),
                            minor.as_str().parse::<i8>().unwrap(),
                            patch.as_str().parse::<i8>().unwrap(),
                        )),
                    _ => None,
                }
            })
            .next()
            .unwrap();

        let (major, minor, patch) = radare_output_version;

        println!("Radare2 Version: {}.{}.{}", major, minor, patch);

        major >= constants::EXPECTED_RADARE_MAJOR_VERSION
    }

    pub fn is_ntoskrnl_valid() -> bool {
        let ntoskrnl_path: &Path = Path::new(constants::NTOSKRNL_DEFAULT_EXECUTABLE_FILE);

        ntoskrnl_path.exists() && ntoskrnl_path.is_file()
    }

    pub fn download_ntoskrnl_pdb() -> (bool, String) {
        let extracted_pdb: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-c idpd")
            .arg("-qq")
            .arg(constants::NTOSKRNL_DEFAULT_EXECUTABLE_FILE)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(extracted_pdb.stderr).unwrap();

        if !stderr.is_empty() && !stderr.contains("File already downloaded") {
            return (false, stderr);
        }

        (true, String::from_utf8(extracted_pdb.stdout).unwrap().trim().to_string())
    }

    pub fn fetch_ntoskrnl_info() -> core::result::Result<String, errors::OffsetDumperError> {
        let radare_ntoskrnl_file_version: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-c iV")
            .arg("-qq")
            .arg(constants::NTOSKRNL_DEFAULT_EXECUTABLE_FILE)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(radare_ntoskrnl_file_version.stderr).unwrap();

        if !stderr.is_empty() {
            return Err(errors::OffsetDumperError::NtoskrnlDownloadingPdbError);
        }

        let stdout = String::from_utf8(radare_ntoskrnl_file_version.stdout).unwrap();

        let extracted_ntoskrnl_file_version = stdout
            .lines()
            .filter(|&line| line.trim().starts_with(constants::EXPECTED_FILE_VERSION_INFO))
            .collect::<Vec<&str>>();

        if extracted_ntoskrnl_file_version.is_empty() {
            return Err(errors::OffsetDumperError::NtoskrnlVersionNotFoundError);
        }

        Ok(
            extracted_ntoskrnl_file_version
                .last()
                .unwrap()
                .replace(constants::EXPECTED_FILE_VERSION_INFO, "")
                .trim()
                .to_string()
        )
    }

    pub fn dump_ntoskrnl_symbols() -> core::result::Result<
        Vec<OffsetsDump>,
        errors::OffsetDumperError
    > {
        let extracted_pdb: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-c idpi")
            .arg("-qq")
            .arg("-B 0")
            .arg(constants::NTOSKRNL_DEFAULT_EXECUTABLE_FILE)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(extracted_pdb.stderr).unwrap();

        if !stderr.is_empty() && !stderr.contains("invalid type") {
            return Err(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError);
        }

        let mut last_parsed_struct: &str = "";

        let result = String::from_utf8(extracted_pdb.stdout)
            .unwrap()
            .lines()
            .filter(|&line| {
                if line.contains("struct _") && !line.contains(" struct") {
                    last_parsed_struct = line;
                }

                constants::EXPECTED_SYMBOLS
                    .iter()
                    .any(|&s| line.contains(s[0]) && last_parsed_struct.contains(s[1]))
            })
            .collect::<Vec<&str>>()
            .iter()
            .map(|item| {
                let offsets = Regex::new(constants::OFFSETS_REGEX).unwrap().captures(item).unwrap();
                let offset = offsets[0].to_string();
                let index_element = constants::EXPECTED_SYMBOLS
                    .iter()
                    .position(|&i| item.contains(i[0]))
                    .unwrap();
                let splitted_line: Vec<&str> = constants::EXPECTED_SYMBOLS[index_element][0]
                    .split(" ")
                    .collect();

                let kind: String = splitted_line[0..splitted_line.len() - 1].join(" ");
                let name: String =
                    splitted_line[splitted_line.len() - 1..splitted_line.len()][0].to_string();

                OffsetsDump {
                    kind,
                    name,
                    offset,
                }
            })
            .collect::<Vec<OffsetsDump>>();

        if result.len() != constants::EXPECTED_SYMBOLS.len() {
            return Err(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError);
        }

        Ok(result)
    }
}