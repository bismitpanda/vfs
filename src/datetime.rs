#[derive(Clone, Copy, Debug)]
pub struct DateTime {
    hour: u8,
    minute: u8,
    day: u8,
    month: u8,
    year: u16
}

impl DateTime {
    pub fn new(hour: u32, minute: u32, day: u32, month: u32, year: u32) -> Self {
        Self {
            hour: hour as u8,
            minute: minute as u8,
            day: day as u8,
            month: month as u8,
            year: year as u16
        }
    }

    pub fn from_u32(date_time: u32) -> Self {
        let year = (date_time >> 20) as u16;
        let minute = ((date_time >> 14) & 0b111111) as u8;
        let hour = ((date_time >> 9) & 0b11111) as u8;
        let day = ((date_time >> 4) & 0b11111) as u8;
        let month = (date_time & 0b1111) as u8;
        
        Self { hour, minute, day, month, year }
    }

    pub fn to_u32(&self) -> u32 {
        let mut converted: u32 = 0;
        converted |= self.year as u32;
        converted <<= 6;
        converted |= self.minute as u32;
        converted <<= 5;
        converted |= self.hour as u32;
        converted <<= 5;
        converted |= self.day as u32;
        converted <<= 4;
        converted |= self.month as u32;

        converted
    }
}

impl std::fmt::Display for DateTime {
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