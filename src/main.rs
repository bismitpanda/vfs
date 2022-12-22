use std::{
    io::{Write, Read},
    fs::{File, OpenOptions},
    os::windows::prelude::FileExt,
    error::Error,
    collections::HashMap,
};

use aes_gcm::{
    aead::{KeyInit, generic_array::GenericArray},
    Aes256Gcm,
    AesGcm,
    aes::Aes256
};

use sha2::{
    Sha256,
    Digest,
    digest::typenum::{UInt, UTerm, B0, B1}
};

use rkyv::{
    Archive,
    Deserialize,
    Serialize,
    AlignedVec
};
use bytecheck::CheckBytes;

macro_rules! scan {
    () => {{
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line
    }};

    ($var:expr) => {{
        print!("{}", $var);
        match std::io::stdout().flush() {
            Ok(_) => {},
            Err(err) => panic!("{}", err)
        };
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line
    }}
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy)]
#[archive_attr(derive(CheckBytes))]
struct VfsFile {
    offset: u32,
    length: u32
}

#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive_attr(derive(CheckBytes))]
struct Root {
    cur_offset: u32,
    files: Vec<(String, VfsFile)>,
}

#[derive(PartialEq, Eq)]
struct Commands(u8);

impl Commands {
    const EXIT: Self = Self(0);
    const TOUCH: Self = Self(1);
    const CAT: Self = Self(2);
    const NANO: Self = Self(3);
    const CP: Self = Self(4);
    const MV: Self = Self(5);
    const RM: Self = Self(6);
    const LS: Self = Self(7);
    const RESET: Self = Self(8);
    const INVALID: Self = Self(255);

    fn to_command(cmd: &str) -> Self {
        match cmd {
            "exit" | "ext" => Commands::EXIT,
            "touch" | "tch" => Commands::TOUCH,
            "cat" => Commands::CAT,
            "nano" | "nn" => Commands::NANO,
            "cp" => Commands::CP,
            "mv" => Commands::MV,
            "rm" => Commands::RM,
            "ls" => Commands::LS,
            "reset" |"rst" => Commands::RESET,
            _ => Commands::INVALID
        }
    }
}

impl VfsFile {
    fn new(offset: u32, size: usize) -> Self {
        Self {
            offset,
            length: size as u32
        }
    }
}

impl Default for Root {
    fn default() -> Self {
        Root {
            cur_offset: 0,
            files: Vec::new()
        }
    }
}

struct Vfs {
    #[allow(dead_code)]
    key: AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    root: Root,
    file: File,
    registry: HashMap<String, usize>
}

fn get_key() -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
    let key = rpassword::prompt_password("Your key: ").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());

    let cipher_key = hasher.finalize();

    return cipher_key;
}

impl Vfs {
    fn new(path: String) -> Self {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(get_key().as_slice()));
        Vfs {
            root: Root::default(),
            file: OpenOptions::new().write(true).read(true).create(true).open(path).unwrap(),
            key: cipher,
            registry: HashMap::new()
        }
    }

    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let mut meta_len_bytes= [0; 4];
        self.file.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_ne_bytes(meta_len_bytes);

        let mut buf = [0; HEADER_SIZE];
        self.file.seek_read(&mut buf, 4)?;

        if meta_len == 0 {
            self.root = Root::default();
            return Ok(());
        }

        let mut aligned_vec = AlignedVec::new();
        aligned_vec.extend_from_slice(&buf[..(meta_len as usize)]);

        self.root = rkyv::from_bytes::<Root>(&aligned_vec)?;

        for (pos, entry) in self.root.files.iter().enumerate() {
            self.registry.insert(entry.0.clone(), pos);
        }

        println!("{:#?}", self.registry);

        Ok(())
    }

    fn exit(&mut self) -> Result<(), Box<dyn Error>> {
        let bytes = rkyv::to_bytes::<_, HEADER_SIZE>(&self.root)?;
        self.file.seek_write(&(bytes.len() as u32).to_ne_bytes(), 0)?;
        self.file.seek_write(&bytes, 4)?;

        Ok(())
    }

    fn touch(&mut self, name: String) -> Result<(), Box<dyn Error>> {
        if self.registry.get(&name).is_some() {
            return Err("File already exists".into());
        }
        let mut text = String::new();
        let mut line: String = scan!("... ");

        while line.trim_end() != "<< EOF" {
            text.push_str(line.as_str());
            line = scan!("... ");
        }

        self.file.seek_write(&text.as_bytes(), self.root.cur_offset as u64 + HEADER_SIZE as u64 + 4)?;

        self.registry.insert(name.clone(), self.root.files.len());

        self.root.files.push((name, VfsFile::new(self.root.cur_offset, text.len())));
        self.root.cur_offset += text.len() as u32;

        Ok(())
    }

    fn cat(&self, name: String) -> Result<(), Box<dyn Error>> {
        let idx = match self.registry.get(&name) {
            Some(i) => *i,
            None => return Err("File not found".into())
        };

        let file = &self.root.files[idx].1;
        let mut buf = vec![0; file.length as usize];

        self.file.seek_read(&mut buf, (file.offset as u64) + (HEADER_SIZE as u64) + 4)?;
        print!("{}", String::from_utf8(buf)?);

        Ok(())
    }

    fn cp(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let idx = match self.registry.get(&from) {
            Some(i) => *i,
            None => return Err("File not found".into())
        };

        let mut entry = self.root.files[idx].clone();
        entry.0 = to.clone();

        let file = entry.1;
        let mut buf = vec![0; file.length as usize];

        self.file.seek_read(&mut buf, (file.offset as u64) + (HEADER_SIZE as u64) + 4)?;
        self.file.seek_write(buf.as_slice(), (self.root.cur_offset as u64) + 4 + (HEADER_SIZE as u64))?;

        self.registry.insert(to, self.root.files.len());

        self.root.files.push(entry);
        self.root.cur_offset += file.offset;

        Ok(())
    }

    fn mv(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let idx = match self.registry.remove(&from) {
            Some(i) => i,
            None => return Err("File not found".into())
        };

        let mut file = self.root.files.remove(idx);
        file.0 = to.clone();
        self.root.files.insert(idx, file);

        self.registry.insert(to, idx);

        Ok(())
    }

    fn rm(&mut self, name: String) -> Result<(), Box<dyn Error>> {
        let idx = match self.registry.get(&name) {
            Some(i) => *i,
            None => return Err("File not found".into())
        };

        let entry = &self.root.files.remove(idx);
        let file = entry.1;
        let mut buf = vec![0; file.length as usize];

        self.file.seek_write(&mut buf, (file.offset as u64) + (HEADER_SIZE as u64) + 4)?;

        self.registry.remove(&name);

        Ok(())
    }

    fn ls(&self) -> Result<(), Box<dyn Error>> {
        let max = match self.registry.keys().map(String::len).max() {
            Some(max) => if max > 4 { max } else { 4 },
            None => 4
        };

        println!("{:^max$}  {:^max$}", "Name", "Size");
        println!("{0:-<max$}  {0:-<max$}", "");

        for (name, file) in &self.root.files {
            println!("{name:<max$}  {}", file.length);
        }

        Ok(())
    }

    fn reset(&mut self) -> Result<(), Box<dyn Error>> {
        self.registry = HashMap::new();
        self.root = Root::default();

        self.file.sync_all()?;
        let len = self.file.metadata()?.len();

        let buf: Vec<u8> = vec![0; len as usize];
        self.file.seek_write(buf.as_slice(), 0)?;

        Ok(())
    }
}

const HEADER_SIZE: usize = 524288;

// fn main() {
fn main() -> Result<(), Box<dyn Error>> {
    let mut vfs = Vfs::new("path.vfs".to_string());
    vfs.init()?;

    loop {
        let cmd = scan!(">>> ");
        let cmds: Vec<&str> = cmd.trim_end().split(' ').collect();
        match Commands::to_command(cmds[0]) {
            Commands::EXIT => {
                vfs.exit()?;
                break
            },

            Commands::TOUCH => {
                if cmds.len() == 2 {
                    vfs.touch(cmds[1].to_string())?;
                } else {
                    println!("Usage: touch [filename]");
                }
            },

            Commands::CAT => {
                if cmds.len() == 2 {
                    vfs.cat(cmds[1].to_string())?;
                } else {
                    println!("Usage: cat [filename]");
                }
            },

            Commands::NANO => {},

            Commands::CP => {
                if cmds.len() == 3 {
                    vfs.cp(cmds[1].to_string(), cmds[2].to_string())?;
                } else {
                    println!("Usage: cp [from] [to]");
                }
            },

            Commands::MV => {
                if cmds.len() == 3 {
                    vfs.mv(cmds[1].to_string(), cmds[2].to_string())?;
                } else {
                    println!("Usage: mv [from] [to]");
                }
            },

            Commands::RM => {
                if cmds.len() == 2 {
                    vfs.rm(cmds[1].to_string())?;
                } else {
                    println!("Usage: rm [filename]");
                }
            },

            Commands::LS => vfs.ls()?,
            Commands::RESET => vfs.reset()?,
            Commands::INVALID => println!("Invalid command entered `{}`", cmds[0]),
            _ => println!("Unknown Error occured")
        }
    }

    Ok(())

    // let bytes = rkyv::to_bytes::<_, 1024>(&Root::default()).unwrap();
    // let buf: [u8; 4] = bytes[..4].try_into().unwrap();
    // println!("{}, {}, {:?}", bytes.len(), u32::from_ne_bytes(buf), bytes);
    // let root = rkyv::from_bytes::<Root>(&bytes).unwrap();
    // println!("{:#?}", root);
}