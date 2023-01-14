use chrono::{Utc, Timelike, Datelike};
use std::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy, Debug)]
pub struct VfsDateTime {
    hour: u32,
    minute: u32,
    day: u32,
    month: u32,
    year: u32
}

impl VfsDateTime {
    pub fn from_u32(date_time: u32) -> Self {
        Self { 
            hour: (date_time >> 9) & 0b11111,
            minute: (date_time >> 14) & 0b111111,
            day: (date_time >> 4) & 0b11111,
            month: date_time & 0b1111,
            year: date_time >> 20
        }
    }

    pub fn to_u32(&self) -> u32 {
        (((((((self.year << 6) | self.minute) << 5) | self.hour) << 5) | self.day) << 4) | self.month
    }

    pub fn from_datetime() -> Self {
        let dt = Utc::now();
        Self { hour: dt.hour(), minute: dt.minute(), day: dt.day(), month: dt.month(), year: dt.year() as u32 }
    }
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