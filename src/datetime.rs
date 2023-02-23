use chrono::{Utc, Timelike, Datelike};
use std::fmt::{Display, Formatter, Result};

pub struct VfsDateTime {
    hour: u32,
    minute: u32,
    day: u32,
    month: u32,
    year: u32
}

pub trait ToDateTime {
    fn parse_dt(self) -> VfsDateTime;
}

impl ToDateTime for u32 {
    fn parse_dt(self) -> VfsDateTime {
        VfsDateTime {
            year: self >> 20,
            minute: (self >> 14) & 0b111111,
            hour: (self >> 9) & 0b11111,
            day: (self >> 4) & 0b11111,
            month: self & 0b1111
        }
    }
}

pub fn now() -> u32 {
    let cur_time = Utc::now();
    ((((((((cur_time.year() as u32) << 6) | cur_time.minute()) << 5) | cur_time.hour()) << 5) | cur_time.day()) << 4) | cur_time.month()
}

impl Display for VfsDateTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let month = match self.month {
            1 => "Jan",
            2 => "Feb",
            3 => "Mar",
            4 => "Apr",
            5 => "May",
            6 => "Jun",
            7 => "Jul",
            8 => "Aug",
            9 => "Sep",
            10 => "Oct",
            11 => "Nov",
            12 => "Dec",
            _ => "Invalid Month"
        };
        f.write_fmt(format_args!("{} {} {} {}:{}", self.day, month, self.year, self.hour, self.minute))
    }
}