use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context, Result},
    Help, SectionExt,
};
use itertools::Itertools;
use std::{
    borrow::Cow,
    fs::OpenOptions,
    io::{stdout, BufRead, BufWriter, Write},
    os::unix::prelude::OpenOptionsExt,
    process::{Command, Stdio},
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
/// Collect passwords for all encrypted zfs file systems into a self-destructing
/// script (output_file). This script should be configured to run, if present,
/// immediately after reboot.
struct Args {
    /// Do not check entered passwords
    #[arg(long, default_value_t = false)]
    skip_password_check: bool,

    /// Write output to this file (blank is stdout)
    #[arg(long, default_value = "/zfs-reboot-passphrase.sh")]
    output_file: String,
}

struct PasswordPath {
    path: String,
    password: String,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    if unsafe { libc::geteuid() } != 0 {
        return Err(eyre!("Must run as root"));
    }

    let password_paths: Vec<PasswordPath> = filesystems_with_key_status()
        .wrap_err("failed to find encryption-enabled filesystems")?
        .into_iter()
        .filter_map(
            |filesystem| match get_password(&filesystem, args.skip_password_check) {
                Some(password) => Some(PasswordPath {
                    path: filesystem,
                    password,
                }),
                None => {
                    eprintln!("Skipping {}", filesystem);
                    None
                }
            },
        )
        .collect();

    if args.output_file.is_empty() {
        write_reboot_script(&mut stdout(), &password_paths)?;
    } else {
        let mut f = OpenOptions::new()
            .mode(0o700)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&args.output_file)?;
        write_reboot_script(&mut f, &password_paths)?;
        eprintln!("Wrote {}", &args.output_file);
    }

    Ok(())
}

fn write_reboot_script<W>(w: &mut W, password_paths: &Vec<PasswordPath>) -> Result<()>
where
    W: Write,
{
    let mut w = BufWriter::new(w);
    writeln!(w, "#!/bin/bash")?;

    for pp in password_paths {
        writeln!(
            w,
            "echo {} | zfs load-key {}",
            shell_escape::escape(Cow::from(pp.password.clone())),
            pp.path
        )?;
    }

    for pp in password_paths {
        writeln!(w, "zfs mount {}", pp.path)?;
    }

    writeln!(w, "exec shred -u $0")?;

    Ok(())
}

fn check_password(fs: &str, password: String) -> Result<()> {
    let mut load_key = Command::new("zfs")
        .args(["load-key", "-n", fs])
        .stdin(Stdio::piped())
        .spawn()?;

    let mut stdin = load_key.stdin.take().ok_or(eyre!("Failed to open stdin"))?;
    std::thread::spawn(move || {
        stdin
            .write_all(password.as_bytes())
            .expect("Failed to send password to zfs load-key -n");
    });

    let output = load_key.wait()?;
    if !output.success() {
        return Err(eyre!("zfs password check failed"));
    }

    Ok(())
}

fn get_password(fs: &str, skip_password_check: bool) -> Option<String> {
    loop {
        let pass =
            rpassword::prompt_password(format!("Password for {fs} (empty to skip): ")).unwrap();

        if pass.is_empty() {
            return None;
        }

        if skip_password_check {
            return Some(pass);
        }

        match check_password(fs, pass.clone()) {
            Ok(_) => return Some(pass),
            Err(e) => {
                eprintln!("Password verification failed: {}", e);
            }
        }
    }
}

fn filesystems_with_key_status() -> Result<Vec<String>> {
    let output = Command::new("zfs")
        .args(["get", "-H", "-t", "filesystem", "keystatus"])
        .output()
        .wrap_err("failed to run zfs utility")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!("failed to get filesystem with keystatus"))
            .with_section(move || stderr.trim().to_string().header("Stderr:"));
    }

    parse_filesystems_with_key_status(output.stdout)
        .wrap_err("failed to parse filesystems with key status")
}

fn parse_filesystems_with_key_status(
    zfs_get_output: Vec<u8>,
) -> Result<Vec<String>, std::io::Error> {
    fn parse_line(line: &str) -> Option<String> {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields.get(2) {
            Some(&"available") => Some(
                fields
                    .first()
                    .unwrap_or_else(|| {
                        unreachable!("fields.get(2) worked and fields.first() failed")
                    })
                    .to_string(),
            ),
            Some(_) | None => None,
        }
    }

    zfs_get_output
        .lines()
        .filter_map_ok(|l| parse_line(&l))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_write_reboot_script() {
        let mut buf = std::io::BufWriter::new(Vec::new());
        write_reboot_script(
            &mut buf,
            &vec![
                PasswordPath {
                    path: "some_path".to_owned(),
                    password: "hunter1".to_owned(),
                },
                PasswordPath {
                    path: "other_path".to_owned(),
                    password: "hunter2".to_owned(),
                },
            ],
        )
        .unwrap();
        let bytes = buf.into_inner().unwrap();

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            indoc! {"
                #!/bin/bash
                echo hunter1 | zfs load-key some_path
                echo hunter2 | zfs load-key other_path
                zfs mount some_path
                zfs mount other_path
                exec shred -u $0
            "}
        );
    }

    #[test]
    fn parse_filesystems_with_key_status_valid() {
        let zfs_output = indoc! {"
            tank\tkeystatus\t-\t-
            tank/decrypted_fs1\tkeystatus\t-\t-
            tank/encrypted_fs1\tkeystatus\tavailable\t-
            tank/decrypted_fs2\tkeystatus\t-\t-
            tank/encrypted_fs2\tkeystatus\tavailable\t-
        "};

        let got = parse_filesystems_with_key_status(zfs_output.into()).unwrap();

        assert_eq!(got, vec!["tank/encrypted_fs1", "tank/encrypted_fs2"]);
    }
}
