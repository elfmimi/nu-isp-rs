use std::cell::Cell;
use std::convert::TryInto;

use hidapi::HidDevice;

#[allow(unused)]
pub struct PartInfo {
    pub name: &'static str,
    pub flash_size: u32,
}

macro_rules! pdid_map {
    { $( $name:ident { $pdid:expr, $size:expr }, ) + } =>
        ( |pdid| ( match pdid { $(
            $pdid => Some((stringify!($name), $size)),
        ) * _ => None } ).map(|(name, flash_size)| PartInfo{name, flash_size}) );
}

/// Lookup chip product name from its PDID.
pub fn get_partinfo(pdid: u32) -> Option<PartInfo> {
    let pdid_map = pdid_map! {
        // PARTNAME { pdid, flash_size }
        // NUC123ZC2AN { 0x00012345, 36*1024 },
        // NUC123ZD4AN { 0x00012355, 68*1024 },
        // NUC123LC2AN { 0x00012325, 36*1024 },
        NUC123LD4AN { 0x00012335, 68*1024 },
        // NUC123SC2AN { 0x00012305, 36*1024 },
        // NUC123SD4AN { 0x00012315, 68*1024 },
        // NUC123ZC2AE { 0x10012345, 36*1024 },
        // NUC123ZD4AE { 0x10012355, 68*1024 },
        // NUC123LC2AE { 0x10012325, 36*1024 },
        // NUC123LD4AE { 0x10012335, 68*1024 },
        // NUC123SC2AE { 0x10012305, 36*1024 },
        // NUC123SD4AE { 0x10012315, 68*1024 },
        NUC126LE4AE { 0x00C05205, 128*1024 },
        NUC126LG4AE { 0x00C05204, 256*1024 },
        // NUC126SE4AE { 0x00C05213, 128*1024 },
        // NUC126SG4AE { 0x00C05212, 256*1024 },
        // NUC126VG4AE { 0x00C05231, 256*1024 },
    };
    pdid_map(pdid)
}

pub mod error {
    #[derive(Debug)]
    pub enum Error {
        HidError(hidapi::HidError),
        ChecksumError,
        PacketNumberError,
    }

    impl From<hidapi::HidError> for Error {
        fn from(error: hidapi::HidError) -> Self {
            Error::HidError(error)
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match *self {
                Error::HidError(ref err) => write!(f, "{}", err),
                Error::ChecksumError => write!(f, "Checksum Error"),
                Error::PacketNumberError => write!(f, "Packet Number Error"),
            }
        }
    }
}

type Result<T> = std::result::Result<T, error::Error>;

#[derive(Debug)]
pub enum ProgressEvent {
    Started { total_bytes: u32 },
    Erased,
    Programmed { bytes: u32 },
    Finished,
    Aborted,
    StartedErasing,
    FinishedErasing,
    AbortedErasing,
    _Reserved_,
}

pub struct Progress {
    handler: Box<dyn Fn(ProgressEvent)>,
}

impl Progress {
    /// Create a new `Progress` structure with a given `handler` to be called on events.
    // pub fn new(handler: impl Fn(ProgressEvent) + 'static) -> Self {
    pub fn new<F: 'static>(handler: F) -> Self
    where
        F: Fn(ProgressEvent),
    {
        Self {
            handler: Box::new(handler),
        }
    }

    /// Emit a flashing progress event.
    fn emit(&self, event: ProgressEvent) {
        (self.handler)(event);
    }

    pub fn started(&self, total_bytes: u32) {
        self.emit(ProgressEvent::Started { total_bytes });
    }

    pub fn erased(&self) {
        self.emit(ProgressEvent::Erased);
    }

    pub fn programmed(&self, bytes: u32) {
        self.emit(ProgressEvent::Programmed { bytes });
    }

    pub fn finished(&self) {
        self.emit(ProgressEvent::Finished);
    }

    pub fn aborted(&self) {
        self.emit(ProgressEvent::Aborted);
    }
}

mod nu_isp_cmd {
    pub const UPDATE_APROM: u8 = 0xA0;
    pub const READ_CONFIG: u8 = 0xA2;
    pub const SYNC_PACKNO: u8 = 0xA4;
    pub const GET_FWVER: u8 = 0xA6;
    pub const RUN_APROM: u8 = 0xAB;
    pub const RUN_LDROM: u8 = 0xAC;
    pub const CONNECT: u8 = 0xAE;
    pub const GET_DEVICEID: u8 = 0xB1;

    pub const DATA_PACKET: u8 = 0x00;
}

pub struct NuIspInfo {
    pub pdid: u32,
    pub config: [u32; 2],
}

pub struct Context<'a> {
    device: &'a HidDevice,
    progress: &'a Progress,
    rpn: Cell<u32>,
}

impl<'a> Context<'a> {
    pub fn new(device: &'a hidapi::HidDevice, progress: &'a Progress) -> Self {
        Context {
            device,
            progress,
            rpn: Cell::new(0),
        }
    }

    fn nu_isp_connect(self: &Context<'a>) -> Result<NuIspInfo> {
        let d = self.device;
        self.rpn.set(0);

        // CONNECT
        let pn = 1 as u32;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::CONNECT;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
        }
        d.write(&buffer[0..65])?;
        d.read(&mut buffer[0..64])?;
        let rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if rpn != pn + 1 {
            log::debug!("rpn = {:08X}", rpn);
            return Err(error::Error::PacketNumberError);
        }
        log::debug!("CONNECT");

        // SYNC_PACKNO
        let pn = rpn + 1;
        let sync_pn = 0x01234567 as u32;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::SYNC_PACKNO;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
            buffer[8..12].copy_from_slice(&sync_pn.to_le_bytes());
        }
        d.write(&buffer[0..65])?;
        d.read(&mut buffer[0..64])?;
        let rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if rpn != sync_pn + 1 {
            return Err(error::Error::PacketNumberError);
        }
        log::debug!("SYNC rpn: {:08X} ( sent: {:08X} )", rpn, sync_pn);

        // GET_DEVICEID
        let pn = rpn + 1;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::GET_DEVICEID;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
        }
        d.write(&buffer[0..65])?;
        d.read(&mut buffer[0..64])?;
        let rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        let pdid = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        if rpn != pn + 1 {
            return Err(error::Error::PacketNumberError);
        }

        // GET_FWVER
        let pn = rpn + 1;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::GET_FWVER;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
        }
        d.write(&buffer[0..65])?;
        d.read(&mut buffer[0..64])?;
        let rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        let fwver = buffer[8];
        if rpn != pn + 1 {
            return Err(error::Error::PacketNumberError);
        }
        log::info!("FWVER  {:#04X}", fwver);

        // READ_CONFIG
        let pn = rpn + 1;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::READ_CONFIG;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
        }
        d.write(&buffer[0..65])?;
        d.read(&mut buffer[0..64])?;
        let rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if rpn != pn + 1 {
            return Err(error::Error::PacketNumberError);
        }
        let config0 = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        let config1 = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
        log::debug!("CONFIG {:08X}:{:08X}", config0, config1);

        self.rpn.set(rpn);
        Ok(NuIspInfo {
            pdid,
            config: [config0, config1],
        })
    }

    pub fn nu_isp_info(self: &Context<'a>) -> Result<NuIspInfo> {
        self.nu_isp_connect()
    }

    pub fn nu_isp_erase(self: &Context<'a>) -> Result<()> {
        let d = self.device;
        if self.rpn.get() == 0 {
            self.nu_isp_connect()?;
        };

        // This will only erase APROM.
        let rpn = match self.update_aprom(vec![]) {
            Err(err) => {
                self.progress.emit(ProgressEvent::AbortedErasing);
                return Err(err);
            }
            Ok(_) => self.rpn.get(),
        };

        // Reset and reboot the bootloader
        // RUN_LDROM
        let pn = rpn + 1;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::RUN_LDROM;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
        }
        d.write(&buffer[0..65])?;
        // d.read(&mut buffer[0..64])?;
        // let _rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());

        self.rpn.set(0);
        Ok(())
    }

    pub fn nu_isp_download(self: &Context<'a>, binary: Vec<u8>) -> Result<()> {
        // TODO check flash size
        let d = self.device;

        let rpn = self.rpn.get();
        if rpn == 0 {
            self.nu_isp_connect()?;
        };

        // UPDATE_APROM
        let rpn = match self.update_aprom(binary) {
            Err(err) => {
                self.progress.aborted();
                return Err(err);
            }
            Ok(_) => self.rpn.get(),
        };

        // Reset and boot from application
        {
            // RUN_APROM
            let pn = rpn + 1;
            let buffer = &mut [0_u8; 65];
            {
                let buffer = &mut buffer[1..];
                buffer[0] = nu_isp_cmd::RUN_APROM;
                buffer[4..8].copy_from_slice(&pn.to_le_bytes());
            }
            d.write(&buffer[0..65])?;
            // d.read(&mut buffer[0..64])?;
            // let _rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        }

        self.rpn.set(0);
        Ok(())
    }

    fn update_aprom(self: &Context<'a>, data: Vec<u8>) -> Result<()> {
        let d = self.device;
        let rpn = self.rpn.get();
        let len = data.len();

        // if length == 0 we are going to only erase
        if len == 0 {
            self.progress.emit(ProgressEvent::StartedErasing);
        } else {
            self.progress.started(len as u32);
        }

        // UPDATE_APROM
        let pn = rpn + 1;
        let mut rpn;
        let buffer = &mut [0_u8; 65];
        {
            let buffer = &mut buffer[1..];
            buffer[0] = nu_isp_cmd::UPDATE_APROM;
            buffer[4..8].copy_from_slice(&pn.to_le_bytes());
            buffer[8..12].copy_from_slice(&(0_u32).to_le_bytes()); // start address, this is unused
            buffer[12..16].copy_from_slice(&(len as u32).to_le_bytes());
            if len == 0 {
                buffer[16..].copy_from_slice(&[0xFF_u8; 48])
            } else if len >= 48 {
                buffer[16..].copy_from_slice(&data[0..48]);
            } else {
                buffer[16..][..len].copy_from_slice(&data[0..len]);
                buffer[16..][len..].copy_from_slice(&[0xFF_u8; 48][..48 - len]);
            }
        }
        d.write(&buffer[0..65])?;
        let checksum = buffer[1..]
            .iter()
            .fold(0_u16, |sum, &b| sum.wrapping_add(b as u16));
        d.read(&mut buffer[0..64])?;
        let rsum = u16::from_le_bytes(buffer[0..2].try_into().unwrap());
        rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if rsum != checksum {
            return Err(error::Error::ChecksumError);
        }
        if rpn != pn + 1 {
            return Err(error::Error::PacketNumberError);
        }

        if len == 0 {
            self.progress.emit(ProgressEvent::FinishedErasing);
            self.rpn.set(rpn);
            return Ok(());
        }

        self.progress.erased();

        let mut pn = rpn + 1;
        let mut idx = 48;
        while idx < len {
            self.progress.programmed(idx as u32);
            let buffer = &mut [0_u8; 65];
            {
                let buffer = &mut buffer[1..];
                buffer[0] = nu_isp_cmd::DATA_PACKET;
                buffer[4..8].copy_from_slice(&pn.to_le_bytes());
                let len = std::cmp::min(len - idx, 56);
                buffer[8..][..len].copy_from_slice(&data[idx..][..len]);
            }
            d.write(&buffer[0..65])?;
            let checksum = buffer[1..]
                .iter()
                .fold(0_u16, |sum, &b| sum.wrapping_add(b as u16));
            d.read(&mut buffer[0..64])?;
            let rsum = u16::from_le_bytes(buffer[0..2].try_into().unwrap());
            rpn = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
            if rsum != checksum {
                return Err(error::Error::ChecksumError);
            }
            if rpn != pn + 1 {
                return Err(error::Error::PacketNumberError);
            }

            pn = rpn + 1;
            idx += 56;
        }
        self.progress.finished();

        self.rpn.set(rpn);
        return Ok(());
    }
}
