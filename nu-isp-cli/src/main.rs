use std::ops::Not;
use std::path::PathBuf;

extern crate clap;
use clap::{App, AppSettings, Arg, SubCommand};
use maplit::hashmap;

use termcolor::{Color, ColorChoice};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use hidapi::{HidApi, HidDevice};
use ihex::{
    reader::{Reader as HexReader, ReaderError as HexReaderError},
    record::Record as HexRecord,
};

use nu_isp::get_partinfo;
use nu_isp::{Context as NuIspContext, Progress as NuIspProgress, ProgressEvent};

/*
#[derive(Debug)]
enum Error {
    HidError(hidapi::HidError),
    GoblinError(goblin::error::Error),
    HexReaderError(HexReaderError),
    IoError(std::io::Error),
}
*/

macro_rules! error_from_list {
    ( $( $enum:ident ( $error:ty ) ), + ) => {
	#[derive(Debug)]
	enum Error {
	    NoLoadableSection,
	    FileSizeTooLarge,
	    $($enum($error),)*
	}
	$(impl From<$error> for Error { fn from(error: $error) -> Self { Error::$enum(error) } }) *
    }
}

error_from_list!(
    HidError(hidapi::HidError),
    GoblinError(goblin::error::Error),
    HexReaderError(HexReaderError),
    IoError(std::io::Error),
    NuIspError(nu_isp::error::Error)
);

type Result<T> = std::result::Result<T, Error>;

/*
use std::fmt;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            Error::HidError(ref err) => write!(f, "HID error: {}", err),
            Error::GoblinError(ref err) => write!(f, "ELF Parse error: {}", err),
            Error::HexReaderError(ref err) => write!(f, "HEX Parse error: {}", err),
            Error::IoError(ref err) => write!(f, "IO error: {}", err),
        }
    }
}
*/

/*
impl std::error::Error for Error {
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            // N.B. Both of these implicitly cast `err` from their concrete
            // types (either `&io::Error` or `&num::ParseIntError`)
            // to a trait object `&Error`. This works because both error types
            // implement `Error`.
            Error::HidError(ref err) => Some(err),
            Error::GoblinError(ref err) => Some(err),
            Error::HexReaderError(ref err) => Some(err),
            Error::IoError(ref err) => Some(err),
        }
    }
}
*/

macro_rules! error {
    ($err:expr) => {
        log::error!("{}({}): {}", file!(), line!(), $err)
    };
}

// This is ugly. It should be able to do better than this.
#[allow(unused)]
macro_rules! colored {
    ($($arg:tt)*) => {{
	// termcolor fails to auto detect terminal in certain environment
	let color_choise = if atty::is(atty::Stream::Stdout) { ColorChoice::Auto } else { ColorChoice::Never };
	let writer = termcolor::BufferWriter::stdout(color_choise);
	let mut buffer = writer.buffer();
	termcolor_output::colored!(buffer, $($arg)*).unwrap();
	writer.print(&buffer).unwrap();
    }};
}

/*
// For some reason this does not compile.
// The reason seems to be that termcolor_output_impl::colored_derive()
// is not good at parsing macro invocation as a format string.
macro_rules! coloredln {
    ($fmt:tt, $($arg:tt)+) => {
        colored!(concat!($fmt, "\n"), $($arg)+)
    };
}
*/

macro_rules! coloredln {
    ($($arg:tt)*) => {{
	// termcolor fails to auto detect terminal in certain environment
	let color_choise = if atty::is(atty::Stream::Stdout) { ColorChoice::Auto } else { ColorChoice::Never };
	let writer = termcolor::BufferWriter::stdout(color_choise);
	let mut buffer = writer.buffer();
	termcolor_output::colored!(buffer, $($arg)*).unwrap();
	write!(&mut buffer as &mut dyn std::io::Write, "\n").unwrap();
	// above is the same as the following
	/* {
	    use std::io::Write;
	    write!(buffer, "\n").unwrap();
	} */
	writer.print(&buffer).unwrap();
    }};
}

macro_rules! ecoloredln {
    ($($arg:tt)*) => {{
	// termcolor fails to auto detect terminal in certain environment
	let color_choise = if atty::is(atty::Stream::Stderr) { ColorChoice::Auto } else { ColorChoice::Never };
	let writer = termcolor::BufferWriter::stderr(color_choise);
	let mut buffer = writer.buffer();
	termcolor_output::colored!(buffer, $($arg)*).unwrap();
	write!(&mut buffer as &mut dyn std::io::Write, "\n").unwrap();
	writer.print(&buffer).unwrap();
    }};
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let mut app = App::new("Nuvoton NuMicro ISP_HID Programming Tool [unofficial]\nVersion ")
        .setting(AppSettings::DisableHelpSubcommand)
        .setting(AppSettings::DisableVersion)
        .version(VERSION)
        .author(clap::crate_authors!())
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(false)
                .index(1),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("VID")
                .long("vid")
                .takes_value(true)
                .help("vendor id"),
        )
        .arg(
            Arg::with_name("PID")
                .long("pid")
                .takes_value(true)
                .help("product id"),
        )
        .arg(
            Arg::with_name("disable-progressbar")
                .long("disable-progressbar")
                .help("diasble progressbar")
                .alias("no-progress"),
        )
        .arg(
            Arg::with_name("version")
                .short("V")
                .long("version")
                .help("Show version"),
        )
        .subcommand(SubCommand::with_name("info").about("print target information"))
        .subcommand(
            SubCommand::with_name("boot")
                .about("boot into application program ( Reset to APROM )")
                .alias("run")
                .alias("reset")
                .alias("reboot")
                .alias("launch"),
        )
        .subcommand(
            SubCommand::with_name("erase").about("erase APROM ( DATA flash will be kept intact )"),
        )
        .subcommand(
            SubCommand::with_name("flash")
                .about("flash binary to target")
                .arg(
                    Arg::with_name("INPUT")
                        .help("Sets the input file to use")
                        .required(true),
                )
                .alias("write")
                .alias("program")
                .alias("download"),
        );
    let matches = app
        .get_matches_from_safe_borrow(std::env::args())
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            std::process::exit(1)
        });

    // pretty_env_logger::init();
    {
        log::set_max_level(log::LevelFilter::Off);
        let mut builder = pretty_env_logger::formatted_builder();

        let environment_variable_name = "RUST_LOG";
        if let Ok(s) = ::std::env::var(environment_variable_name) {
            builder.parse_filters(&s);
        } else {
            match matches.occurrences_of("v") {
                0 => builder.parse_filters("warn"),
                1 => builder.parse_filters("info"),
                2 => builder.parse_filters("debug"),
                3 | _ => builder.parse_filters("trace"),
            };
        }

        builder.try_init().unwrap();
    }

    log::trace!("initialized logger");

    let info = matches.subcommand_matches("info").is_some();
    if info {
        println!("Printing info...");
    }

    let mut vid_pid: Option<(u16, u16)> = None;
    let mut input: Option<&str> = None;
    if let Some(flash) = matches.subcommand_matches("flash") {
        let file = flash.value_of("INPUT").unwrap();
        input = Some(file)
    }

    if matches.is_present("flash")
        || matches.is_present("info")
        || matches.is_present("erase")
        || matches.is_present("boot")
    {
        if let Some(param) = matches.value_of("INPUT") {
            let pv: Vec<u16> = param
                .split(':')
                .map(|item| u16::from_str_radix(item, 16).unwrap())
                .collect();
            if pv.len() == 2 {
                vid_pid = Some((pv[0], pv[1]))
            }
        }
    } else if let Some(file) = matches.value_of("INPUT") {
        input = Some(file)
    } else {
        coloredln!(
            "{}{}Nuvoton{} {}NuMicro {}ISP_HID {}Programming {}Tool {}[unofficial]{}",
            fg!(Some(Color::Ansi256(196))),
            bold!(true),
            bold!(false),
            fg!(Some(Color::Ansi256(202))),
            fg!(Some(Color::Ansi256(208))),
            fg!(Some(Color::Ansi256(214))),
            fg!(Some(Color::Ansi256(220))),
            fg!(Some(Color::Ansi256(244))),
            reset!()
        );
        coloredln!(
            "{}Version {}{}",
            fg!(Some(Color::Ansi256(226))),
            VERSION,
            reset!()
        );

        let exe = std::env::current_exe();
        let bin_name = exe
            .as_ref()
            .ok()
            .and_then(|p| p.file_stem())
            .and_then(|f| f.to_str())
            .unwrap_or("nu-isp-cli");

        if matches.is_present("version").not() {
            println!("\nQuick Reference:\n");
            println!("    {} <INPUT>\n", bin_name);
            println!("    {} info\n", bin_name);
            println!("    {} erase\n", bin_name);
            println!("    {} flash <INPUT>\n", bin_name);
            println!("    {} <VID:PID> info\n", bin_name);
            println!("    {} <VID:PID> erase\n", bin_name);
            println!("    {} <VID:PID> flash <INPUT>\n", bin_name);
            println!("    {} --help", bin_name);
        }
        return;
    }

    if matches.is_present("VID") && matches.is_present("PID") {
        let vid = matches.value_of("VID").unwrap();
        let pid = matches.value_of("PID").unwrap();
        let vid = u16::from_str_radix(vid, 16).unwrap();
        let pid = u16::from_str_radix(pid, 16).unwrap();
        if vid_pid.is_some() && vid_pid != Some((vid, pid)) {
            error!("PID:VID should be specified only once");
            std::process::exit(1)
        }
        vid_pid = Some((vid, pid))
    }

    let progress_event_handler = {
        let pb = ProgressBar::hidden();
        let template = "{msg:.color1.bold} {spinner:.color1} [{elapsed_precise}] [{bar:25.cyan/blue}] {bytes}/{total_bytes}";
        let template_erase = "{msg:.color1.bold} {spinner:.color1} [{elapsed_precise}]";
        let style = ProgressStyle::default_bar()
            .tick_chars("⠁⠁⠉⠙⠚⠒⠂⠂⠒⠲⠴⠤⠄⠄⠤⠠⠠⠤⠦⠖⠒⠐⠐⠒⠓⠋⠉⠈⠈ ")
            .progress_chars("##-");
        move |event| {
            use ProgressEvent::*;
            match event {
                Started { total_bytes } => {
                    pb.set_style(
                        style
                            .clone()
                            .template(&template.replace("color1", "yellow")),
                    );
                    pb.set_message("    Erasing");
                    pb.set_length(total_bytes as u64);
                    pb.set_position(0);
                    pb.set_draw_target(ProgressDrawTarget::stderr());
                    pb.enable_steady_tick(120);
                }
                Erased => {
                    // Started Programming
                    pb.disable_steady_tick();
                    pb.set_style(style.clone().template(&template.replace("color1", "cyan")));
                    pb.set_message("Programming");
                    pb.enable_steady_tick(120);
                }
                Programmed { bytes, .. } => {
                    pb.set_position(bytes as u64);
                }
                Finished => {
                    pb.disable_steady_tick();
                    pb.set_style(
                        style
                            .clone()
                            .template(&template.replace("color1", "green"))
                            .tick_chars("✔"),
                    );
                    pb.finish_with_message("  Completed");
                }
                Aborted => {
                    pb.disable_steady_tick();
                    let style = style.clone();
                    pb.set_style(
                        style
                            .clone()
                            .template(&template.replace("color1", "red"))
                            .tick_chars("✘"),
                    );
                    pb.abandon_with_message("    Aborted");
                }
                StartedErasing => {
                    pb.set_style(
                        style
                            .clone()
                            .template(&template_erase.replace("color1", "yellow")),
                    );
                    pb.set_message("    Erasing");
                    pb.set_draw_target(ProgressDrawTarget::stderr());
                    pb.enable_steady_tick(120);
                }
                FinishedErasing => {
                    pb.disable_steady_tick();
                    pb.set_style(
                        style
                            .clone()
                            .template(&template_erase.replace("color1", "green"))
                            .tick_chars("✔"),
                    );
                    pb.finish_with_message("  Completed");
                }
                AbortedErasing => {
                    pb.disable_steady_tick();
                    pb.set_style(
                        style
                            .clone()
                            .template(&template_erase.replace("color1", "red"))
                            .tick_chars("✘"),
                    );
                    pb.abandon_with_message("    Aborted");
                }
                _ => {}
            }
        }
    };
    let progress = if matches.is_present("disable-progressbar") {
        NuIspProgress::new(|_| {})
    } else {
        NuIspProgress::new(progress_event_handler)
    };

    let api = HidApi::new().expect("Couldn't find system usb");

    let (d, v, p) = if let Some((v, p)) = vid_pid {
        match api.open(v, p) {
            Err(e) => {
                error!(e);
                eprintln!("Are you sure device is plugged in and in bootloader mode?");
                std::process::exit(1)
            }
            Ok(device) => (device, v, p),
        }
    } else {
        // no vid:pid provided

        let mut device: Option<(HidDevice, u16, u16)> = None;

        let vendor = hashmap! {
            0x0416 => vec![0xA316, 0x3F00],
        };

        for device_info in api.device_list() {
            if let Some(products) = vendor.get(&device_info.vendor_id()) {
                if products.contains(&device_info.product_id()) {
                    if let Ok(d) = device_info.open_device(&api) {
                        device = Some((d, device_info.vendor_id(), device_info.product_id()));
                        break;
                    }
                }
            }
        }
        if device.is_none() {
            eprintln!("Are you sure device is plugged in and in bootloader mode?");
            std::process::exit(1)
        }
        device.unwrap()
    };

    log::info!(
        "found {:04X}:{:04X} ( {:?} {:?} )",
        v,
        p,
        d.get_manufacturer_string().expect("no mfg str").unwrap(),
        d.get_product_string().expect("no prd str").unwrap()
    );

    let context = NuIspContext::new(&d, &progress);

    let do_info = |context: &NuIspContext| {
        let info = context
            .nu_isp_info()
            .map_err(|err| {
                eprintln!("{}!", err);
                ecoloredln!(
                    "{}{}ERROR!{} {:?}",
                    fg!(Some(Color::Red)),
                    bold!(true),
                    reset!(),
                    err
                );
                std::process::exit(1)
            })
            .unwrap();
        match get_partinfo(info.pdid) {
            None => println!("DEVICE PDID: {:08X}", info.pdid),
            Some(partinfo) => coloredln!(
                "DEVICE {}{}{} (PDID: {:08X})",
                bold!(true),
                partinfo.name,
                reset!(),
                info.pdid
            ),
        }
        println!("CONFIG {:08X}:{:08X}", info.config[0], info.config[1]);
    };

    if matches.is_present("info") {
        do_info(&context);
        println!("Done.");
    } else if matches.is_present("boot") {
        println!("Reboot to APROM...");
        // do_info(&context);
        context
            .nu_isp_launch()
            .map_err(|err| {
                eprintln!("{}!", err);
                ecoloredln!(
                    "{}{}ERROR!{} {:?}",
                    fg!(Some(Color::Red)),
                    bold!(true),
                    reset!(),
                    err
                );
                std::process::exit(1)
            })
            .unwrap();
    } else if matches.is_present("erase") {
        println!("Erasing APROM...");
        do_info(&context);
        context
            .nu_isp_erase()
            .map_err(|err| {
                eprintln!("{}!", err);
                ecoloredln!(
                    "{}{}ERROR!{} {:?}",
                    fg!(Some(Color::Red)),
                    bold!(true),
                    reset!(),
                    err
                );
                std::process::exit(1)
            })
            .unwrap();
        coloredln!(
            "{}Erased{} and Rebooting...",
            fg!(Some(Color::Yellow)),
            reset!()
        );
    } else if let Some(file) = input {
        log::info!("input file: {}", file);
        let path = std::path::Path::new(file);
        match std::fs::File::open(path) {
            Ok(file) => drop(file),
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        };
        load_binary_file(path.to_path_buf())
            .and_then(|binary| {
                do_info(&context);
                let start_time = std::time::Instant::now();
                let len = binary.len();
                match context.nu_isp_download(binary) {
                    Ok(ok) => {
                        println!(
                            "  {} bytes in {:.3} sec",
                            len,
                            start_time.elapsed().as_secs_f32()
                        );
                        Ok(ok)
                    }
                    Err(err) => {
                        eprintln!("{}!", err);
                        Err(err.into())
                    }
                }
            })
            .map_err(|err| {
                ecoloredln!(
                    "{}{}ERROR!{} {:?}",
                    fg!(Some(Color::Red)),
                    bold!(true),
                    reset!(),
                    err
                );
                std::process::exit(1)
            })
            .unwrap();
        coloredln!(
            "{}{}SUCCESS!{} and launching...",
            fg!(Some(Color::Green)),
            bold!(true),
            reset!()
        );
    }
}

fn load_binary_file(path: PathBuf) -> Result<Vec<u8>> {
    let is_elf = match std::fs::File::open(&path)? {
        mut file => {
            use std::io::Read;
            let mut buf = [0; 4];
            file.read(&mut buf)?;
            buf == [0x7F, b'E', b'L', b'F']
        }
    };
    match path.extension() {
        _ if is_elf => load_elf(path),
        Some(ext) if ext == "hex" => load_hex(path),
        _ => load_bin(path),
    }
}

fn load_elf(path: PathBuf) -> Result<Vec<u8>> {
    use goblin::elf::program_header::*;
    use std::io::prelude::*;

    let mut buffer = vec![];
    let mut file = std::fs::File::open(path)?;
    file.read_to_end(&mut buffer)?;

    let mut flash_buf = [0xFF_u8; 256 * 1024];
    let mut flash_end = 0;

    let binary = goblin::elf::Elf::parse(&buffer.as_slice())?;
    for ph in &binary.program_headers {
        if ph.p_type == PT_LOAD && ph.p_filesz > 0 {
            // log::debug!("Found loadable segment.");
            // eprintln!("addr: {:08X} size: {:08X}", ph.p_paddr as u32, ph.p_filesz as usize);
            if ph.p_paddr + ph.p_filesz <= flash_buf.len() as u64 {
                let data = &buffer[ph.p_offset as usize..][..ph.p_filesz as usize];
                flash_buf[ph.p_paddr as usize..][..ph.p_filesz as usize].copy_from_slice(data);
                if (ph.p_paddr + ph.p_filesz) > flash_end {
                    flash_end = ph.p_paddr + ph.p_filesz
                }
            }
        }
    }
    if flash_end == 0 {
        error!("No loadable section found in the ELF file.");
        Err(Error::NoLoadableSection)
    } else {
        Ok(flash_buf[0..flash_end as usize].to_vec())
    }
}

fn load_hex(path: PathBuf) -> Result<Vec<u8>> {
    use std::io::prelude::*;

    let mut buffer = vec![];
    let mut file = std::fs::File::open(path)?;
    file.read_to_end(&mut buffer)?;

    let mut flash_buf = [0xFF_u8; 256 * 1024];
    let mut flash_end = 0;

    // let utf8str = Reader::new(str::from_utf8(buffer.as_slice()).unwrap());
    let u8str: String = buffer.iter().map(|&b| b as char).collect();

    let mut linear_offset = 0 as u32;
    HexReader::new(&u8str).try_for_each(|item| match item {
        Err(err) => {
            error!(err);
            Err(err)
        }
        Ok(HexRecord::ExtendedSegmentAddress(segment_addr)) => {
            linear_offset = (segment_addr as u32) << 4;
            Ok(())
        }
        Ok(HexRecord::ExtendedLinearAddress(linear_addr)) => {
            linear_offset = (linear_addr as u32) << 16;
            Ok(())
        }
        Ok(HexRecord::Data { offset, value }) => {
            let offset = linear_offset as usize + offset as usize;
            flash_buf[offset..][..value.len()].copy_from_slice(&value);
            if (offset + value.len()) > flash_end {
                flash_end = offset + value.len()
            }
            Ok(())
        }
        _ => Ok(()),
    })?;

    Ok(flash_buf[0..flash_end as usize].to_vec())
}

fn load_bin(path: PathBuf) -> Result<Vec<u8>> {
    use std::io::prelude::*;

    let mut buffer = vec![];
    let mut file = std::fs::File::open(path)?;
    file.read_to_end(&mut buffer)?;

    let mut flash_buf = [0xFF_u8; 256 * 1024];
    let flash_end;

    if buffer.len() > flash_buf.len() {
        error!("File size too large!");
        return Err(Error::FileSizeTooLarge);
    }
    flash_end = buffer.len();
    flash_buf[0..flash_end].copy_from_slice(&buffer);

    Ok(flash_buf[0..flash_end as usize].to_vec())
}
