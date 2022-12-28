use chrono::{Utc, Timelike, Datelike};

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

impl std::fmt::Display for VfsDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let month = match self.month {
            1 => "January",
            2 => "February",
            3 => "March",
            4 => "April",
            5 => "May",
            6 => "June",
            7 => "July",
            8 => "August",
            9 => "September",
            10 => "October",
            11 => "November",
            12 => "December",
            _ => "Invalid Month"
        };
        write!(f, "{} {} {} {}:{}", self.day, month, self.year, self.hour, self.minute)
    }
}