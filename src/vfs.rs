use crate::datetime::ToDateTime;
use crate::datetime;

use std::{
    io::{Write, Read, Seek, SeekFrom},
    fs::{File, OpenOptions},
    error::Error,
    collections::{BTreeMap, btree_map::Entry::{Occupied, Vacant}},
    cmp::Ordering,
    path::{PathBuf, Path, Component}
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce
};

use rkyv::{
    Archive,
    Deserialize,
    Serialize,
    AlignedVec
};

use snap::raw::{Decoder, Encoder};
use sha2::{Sha256, Digest};
use generic_array::GenericArray;
use typenum::U32;
use bytecheck::CheckBytes;
use colored::*;

#[macro_export]
macro_rules! scan {
    ($var:expr, $vfs:ident) => {{
        print!("{} {}", format!("[vfs][{}]", $vfs.cur_directory.display().to_string()).yellow(), $var);
        if let Err(err) = std::io::stdout().flush() {
            Err::<String, Box<dyn std::error::Error>>(format!("{}", err).into())
        } else {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            Ok(line)
        }
    }}
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive_attr(derive(CheckBytes))]
struct VfsFile {
    offset: usize,
    length: usize,
    display_length: usize,
    date_time: u32,
    nonce: [u8; 12],
    checksum: Vec<u8>
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive_attr(derive(CheckBytes))]
enum VfsEntry {
    File(VfsFile),
    Directory(VfsDirectory)
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive(bound(serialize = "__S: rkyv::ser::ScratchSpace + rkyv::ser::Serializer"))]
#[archive_attr(derive(CheckBytes),check_bytes(bound = "__C: rkyv::validation::ArchiveContext, <__C as rkyv::Fallible>::Error: std::error::Error"))]
struct VfsDirectory {
    date_time: u32,
    #[omit_bounds]
    #[archive_attr(omit_bounds)]
    entries: BTreeMap<String, VfsEntry>
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(bound(serialize = "__S: rkyv::ser::ScratchSpace + rkyv::ser::Serializer"))]
#[archive_attr(derive(CheckBytes),check_bytes(bound = "__C: rkyv::validation::ArchiveContext, <__C as rkyv::Fallible>::Error: std::error::Error"))]
struct Root {
    cur_offset: usize,
    #[omit_bounds]
    #[archive_attr(omit_bounds)]
    entries: BTreeMap<String, VfsEntry>,
    free: BTreeMap<usize, usize>
}

pub struct Vfs {
    oracle: Aes256Gcm,
    encoder: Encoder,
    decoder: Decoder,
    hasher: Sha256,
    root: Root,
    file: File,
    pub cur_directory: PathBuf,
}

impl VfsFile {
    fn new(offset: usize, length: usize, nonce: [u8; 12], display_length: usize, date_time: u32, checksum: Vec<u8>) -> Self {
        Self {
            offset,
            length,
            display_length,
            nonce,
            date_time,
            checksum
        }
    }
}

impl VfsDirectory {
    fn new(entries: BTreeMap<String, VfsEntry>, date_time: u32) -> Self {
        Self { entries, date_time }
    }

    fn default() -> Self {
        Self::new(BTreeMap::new(), 0)
    }
}

impl Default for Root {
    fn default() -> Self {
        Root {
            cur_offset: 0,
            entries: BTreeMap::from([
                (r"\".to_string(), VfsEntry::Directory(VfsDirectory::default()))
            ]),
            free: BTreeMap::new(),
        }
    }
}

fn get_key(prompt: &str) -> GenericArray<u8, U32> {
    let key = rpassword::prompt_password(prompt).unwrap();
    let cipher_key = Sha256::digest(key.as_bytes());

    return cipher_key;
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::RootDir => ret.push(component.as_os_str()),
            Component::ParentDir => {
                ret.pop();
            },
            Component::Normal(c) => ret.push(c),
            _ => {}
        }
    }

    ret
}

enum Action {
    Create(VfsEntry),
    Delete,
    Update(VfsEntry)
}

use crate::vfs::Action::{Create, Delete, Update};

const FILE_DOES_NOT_EXIST: &str = "File doesn't exist";
const FOLDER_DOES_NOT_EXIST: &str = "Folder doesn't exist";
const ERROR_DURING_ENC: &str = "Error occured during encryption";
const ERROR_DURING_DEC: &str = "Error occured during decryption";

const OK: Result<(), Box<dyn Error>> = Ok(());

impl Vfs {
    pub fn new(path: String) -> Self {
        let exists = Path::new(&path).exists();
        let mut file = OpenOptions::new().write(true).read(true).create(true).open(path.clone()).unwrap();

        let cipher = Aes256Gcm::new(&get_key(if exists { "Your key" } else { "Enter a new key: " }));

        if !exists {
            file.write_all(b"vfs\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
            file.flush().unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
        }

        Vfs {
            oracle: cipher,
            root: Root::default(),
            encoder: Encoder::new(),
            decoder: Decoder::new(),
            hasher: Sha256::new(),
            cur_directory: Path::new(r"\").join(""),
            file,
        }
    }

    fn get_path(&self, cur_path: String) -> Result<VfsEntry, Box<dyn Error>> {
        let binding = self.make_path(cur_path);
        let mut path = binding.iter();
        let mut entry = self.root.entries[path.next().unwrap()].clone();
        for part in path {
            match entry {
                VfsEntry::Directory(dir) => {
                    entry = match dir.entries.get(part) {
                        Some(e) => e.clone(),
                        None => return Err(format!("Directory `{part}` not found.").into()),
                    }
                },

                VfsEntry::File(_) => return Err(format!("`{part}` is not a directory").into())
            }
        }

        Ok(entry)
    }

    fn set_path(&mut self, cur_path: String, action: Action) -> Result<(), Box<dyn Error>> {
        let path = self.make_path(cur_path);
        let mut entry = self.root.entries.entry(path[0].clone()).or_insert(
            VfsEntry::Directory(
                VfsDirectory::default()
            )
        );

        let (last, parts) = path[1..].split_last().unwrap();
        for part in parts {
            match entry.clone() {
                VfsEntry::Directory(dir) => {
                    match dir.entries.get(part) {
                        Some(e) => e.clone_into(&mut entry),
                        None => return Err(format!("Directory `{part}` not found.").into()),
                    }
                },

                VfsEntry::File(_) => return Err(format!("`{part}` is not a directory").into())
            }
        }

        let date_time = datetime::now();

        if let VfsEntry::Directory(dir) = entry {
            match action {
                Create(action_entry) => {
                    match dir.entries.entry(last.clone()) {
                        Occupied(entry) => return Err((if let VfsEntry::File(_) = entry.get() { "File already exists." } else { "Folder already exists." }).into()),
                        Vacant(entry) => {
                            dir.date_time = date_time;
                            entry.insert(action_entry)
                        }
                    };
                },

                Delete => {
                    match dir.entries.entry(last.clone()) {
                        Occupied(entry) => {
                            dir.date_time = date_time;
                            entry.remove()
                        },
                        Vacant(_) => return Err("Entry doesn't exist".into())
                    };
                },

                Update(action_entry) => {
                    match dir.entries.entry(last.clone()) {
                        Occupied(mut entry) => {
                            dir.date_time = date_time;
                            entry.insert(action_entry)
                        },
                        Vacant(_) => return Err(if let VfsEntry::File(_) = action_entry { FILE_DOES_NOT_EXIST.into() } else { FOLDER_DOES_NOT_EXIST.into() })
                    };
                }
            }
        }

        OK
    }

    pub fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let len = self.file.metadata()?.len();
        if len < 20 {
            return Err(format!("The file provided is corrupt. len: {len}").into());
        }

        let mut header = [0; 4];
        let header_size = self.file.read(&mut header)?;

        let mut meta_len_bytes= [0; 8];
        let meta_len_size = self.file.read(&mut meta_len_bytes)?;
        let meta_len = usize::from_ne_bytes(meta_len_bytes);

        let mut meta_off_bytes= [0; 8];
        let meta_off_size = self.file.read(&mut meta_off_bytes)?;
        let meta_off = u64::from_ne_bytes(meta_off_bytes);

        if header_size != 4 || header != *b"vfs\0" || meta_len_size != 8 || meta_off_size != 8 {
            return Err("The file provided is corrupted.".into());
        }

        if meta_len == 0 {
            self.root = Root::default();
            return OK;
        }

        let new_buf = &mut vec![0; meta_len];
        self.file.seek(SeekFrom::Start(meta_off + 20))?;
        self.file.read_exact(new_buf)?;

        self.file.seek(SeekFrom::Start(20))?;

        let nonce = Nonce::from_slice(b"secure nonce");

        let decompressed = self.decoder.decompress_vec(new_buf.as_slice())?;
        let decrypted_buf = match self.oracle.decrypt(&nonce, decompressed.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(ERROR_DURING_DEC.into())
        };

        let mut aligned_vec = AlignedVec::new();
        aligned_vec.extend_from_slice(decrypted_buf.as_slice());

        self.root = rkyv::from_bytes::<Root>(&aligned_vec)?;

        OK
    }

    fn make_path(&self, path: String) -> Vec<String> {
        normalize_path(
            self.cur_directory
                .join(path)
                .as_path()
            ).iter()
            .map(|part| part.to_str().unwrap().to_string())
            .collect()
    }

    fn encrypt(&mut self, buf: &[u8], nonce: [u8; 12]) -> Result<Vec<u8>, Box<dyn Error>> {
        match self.oracle.encrypt(&Nonce::from_slice(&nonce), buf) {
            Ok(v) => {
                self.compress(v.as_slice())
            },
            Err(_) => Err(ERROR_DURING_ENC.into())
        }
    }

    fn compress(&mut self, buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let compressed = self.encoder.compress_vec(buf)?;
        Ok(compressed)
    }

    fn read_encrypted(&mut self, length: usize, offset: u64, nonce: [u8; 12]) -> Result<Vec<u8>, Box<dyn Error>> {
        let new_buf = &mut vec![0; length];
        self.file.seek(SeekFrom::Start(offset + 20))?;
        self.file.read_exact(new_buf)?;

        let nonce = Nonce::from_slice(&nonce);

        let decrypted_buf = match self.oracle.decrypt(&nonce, self.decoder.decompress_vec(new_buf.as_slice())?.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(ERROR_DURING_DEC.into())
        };

        Ok(decrypted_buf)
    }

    fn check_file(&mut self, file: VfsFile, path: String) -> Result<(), Box<dyn Error>> {
        let buf = &mut vec!(0; file.length);

        self.file.seek(SeekFrom::Start(file.offset as u64 + 20))?;
        self.file.read_exact(buf)?;

        self.hasher.update(buf.as_slice());

        if file.checksum != self.hasher.finalize_reset().to_vec() {
            return Err(format!("{}: checksum doesn't match", path).into());
        }

        OK
    }

    fn check_dir(&mut self, dir: VfsDirectory, path: String) -> Result<(), Box<dyn Error>> {
        for (name, entry) in dir.entries {
            let res = match entry {
                VfsEntry::File(file) => self.check_file(file, [path.clone(), name].join("/")),
                VfsEntry::Directory(dir) => self.check_dir(dir, [path.clone(), name].join("/"))
            };

            if let Err(err) = res {
                return  Err(err);
            }
        }

        OK
    }

    fn seek_write(&mut self, buf: &[u8], offset: u64) -> Result<usize, Box<dyn Error>> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(buf.len())
    }
}

impl Vfs {
    pub fn exit(&mut self) -> Result<(), Box<dyn Error>> {
        let bytes = rkyv::to_bytes::<_, 2048>(&self.root)?;
        let enc_bytes = self.encrypt(bytes.as_slice(), *b"secure nonce")?;
        let len = self.seek_write(&enc_bytes, self.root.cur_offset as u64 + 20)?;

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(b"vfs\0")?;
        self.file.write_all(&len.to_ne_bytes())?;
        self.file.write_all(&self.root.cur_offset.to_ne_bytes())?;

        OK
    }

    pub fn touch(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let mut text = String::new();
        let mut line = scan!(".. ", self)?;

        while !line.trim_end().ends_with("<< EOF") {
            text.push_str(line.as_str());
            line = scan!(".. ", self)?;
        }

        line = line.trim_end().to_string();

        text.push_str(&line[..(line.len() - 6)]);

        let nonce: [u8; 12] = rand::random();

        let enc = self.encrypt(text.as_bytes(), nonce)?;
        let date_time = datetime::now();

        self.hasher.update(&enc);
        let checksum = self.hasher.finalize_reset().to_vec();

        match self.root.free.iter().position(|(&len, _)| enc.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                let len = self.seek_write(enc.as_slice(), offset as u64 + 20)?;

                self.set_path(
                    path,
                    Create(
                        VfsEntry::File(
                            VfsFile::new(
                                offset,
                                len,
                                nonce,
                                text.len(),
                                date_time,
                                checksum
                            )
                        )
                    )
                )?;

                if len < key {
                    self.root.free.insert(key - len, offset + len);
                }
            },

            None => {
                let len = self.seek_write(enc.as_slice(), self.root.cur_offset as u64 + 20)?;

                self.set_path(
                    path,
                    Create(
                        VfsEntry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce,
                                text.len(),
                                date_time,
                                checksum
                            )
                        )
                    )
                )?;

                self.root.cur_offset += len;
            }
        };

        OK
    }

    pub fn cat(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(path.clone())?;

        if let VfsEntry::File(file) = entry {
            let buf = self.read_encrypted(file.length, file.offset as u64, file.nonce)?;
            println!("{}", String::from_utf8(buf)?);
        } else {
            return Err(format!("{path} is not a file").into());
        }

        OK
    }

    pub fn cp(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(from.clone())? {
            VfsEntry::File(file) => file,
            VfsEntry::Directory(_) => return Err(format!("`{from}` is not a file.").into())
        };

        let buf = &mut vec![0; file.length];

        self.file.seek(SeekFrom::Start((file.offset as u64) + 20))?;
        self.file.read_exact(buf)?;

        let date_time = datetime::now();

        match self.root.free.iter().position(|(&len, _)| file.length <= len) {
            Some(len) => {
                let offset = self.root.free.remove(&len).unwrap();
                self.seek_write(&buf.as_slice(), offset as u64 + 20)?;

                self.set_path(to, Create(VfsEntry::File(VfsFile { offset, date_time, ..file }))
                )?;

                if file.length < len {
                    self.root.free.insert(len - file.length, offset + file.length);
                }
            },

            None => {
                self.seek_write(buf.as_slice(), (self.root.cur_offset as u64) + 20)?;

                self.set_path(to, Create(VfsEntry::File(VfsFile { offset: self.root.cur_offset, date_time, ..file })))?;

                self.root.cur_offset += file.offset;
            }
        }

        OK
    }

    pub fn mv(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(from.clone())? {
            VfsEntry::File(file) => file,
            VfsEntry::Directory(_) => return Err("`mv` for directories are not currently implemented".into())
        };

        self.set_path(from, Delete)?;
        self.set_path(to, Create(VfsEntry::File(file)))
    }

    pub fn rm(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            VfsEntry::File(file) => file,
            VfsEntry::Directory(_) => return Err(format!("`{path}` is not a file.\n{}", "Use `rmdir` instead.".green()).into())
        };

        let mut buf = vec![0; file.length];
        self.seek_write(&mut buf, (file.offset as u64) + 20)?;

        self.set_path(path, Delete)
    }

    pub fn ls(&self) -> Result<(), Box<dyn Error>> {
        let directory = match self.get_path("./".to_string())? {
            VfsEntry::Directory(dir) => dir,
            VfsEntry::File(_) => return Err(format!("Working directory is not a file").into())
        };

        let dir_name_max = match directory.entries.keys().map(String::len).max() {
            Some(max) if max > 4 => max,
            _ => 4
        };

        let width = 17;
        let max = match directory.entries.values().map(|val| {
            match val {
                VfsEntry::Directory(dir) => dir.entries.len(),
                VfsEntry::File(f) => f.display_length
            }
        }).max() {
            Some(m) if m > 9999 => m.to_string().len(),
            _ => 4
        };

        println!("{:^dir_name_max$}   Type   {:^max$}   {:^width$}", "Name", "Size", "Date");
        println!("{0:-<dir_name_max$}   ----   {0:-<max$}   {0:-<width$}", "");

        for (path, entry) in &directory.entries {
            match entry {
                VfsEntry::File(file) => println!("{path:dir_name_max$}   File   {:^max$}   {:^width$}", file.display_length, file.date_time.parse_dt()),
                VfsEntry::Directory(dir) => println!("{path:dir_name_max$}   Dir    {:^max$}   {:^width$}", dir.entries.len(), dir.date_time.parse_dt())
            }
        }

        OK
    }

    pub fn reset(&mut self) -> Result<(), Box<dyn Error>> {
        self.root = Root::default();

        self.file.sync_all()?;
        let len = self.file.metadata()?.len();

        let buf: Vec<u8> = vec![0; len as usize];
        self.seek_write(buf.as_slice(), 0)?;

        OK
    }

    pub fn cd(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        self.get_path(path.clone())?;
        self.cur_directory = normalize_path(&self.cur_directory.join(path).as_path());

        OK
    }

    pub fn mkdir(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        self.set_path(path, Create(VfsEntry::Directory(VfsDirectory::new(BTreeMap::new(), datetime::now()))))
    }

    pub fn pwd(&self) -> Result<(), Box<dyn Error>> {
        Ok(println!("{}", self.cur_directory.display()))
    }

    pub fn rmdir(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let dir = match self.get_path(path.clone())? {
            VfsEntry::File(_) => return Err(format!("`{path}` is not a directory. use `rm` instead.").into()),
            VfsEntry::Directory(dir) => dir
        };

        for (name, entry) in dir.entries {
            match entry {
                VfsEntry::File(_) => self.rm(vec![path.clone(), name].join("/"))?,
                VfsEntry::Directory(_) => self.rmdir(vec![path.clone(), name].join("/"))?
            }
        }

        self.set_path(path, Delete)
    }

    pub fn import(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {

        let mut file = File::open(from)?;
        let text = &mut Vec::new();
        file.read_to_end(text)?;

        let nonce: [u8; 12] = rand::random();

        let enc = self.encrypt(text.as_slice(), nonce)?;
        let date_time = datetime::now();

        self.hasher.update(enc.as_slice());
        let checksum = self.hasher.finalize_reset().to_vec();

        match self.root.free.iter().position(|(&len, _)| enc.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                let len = self.seek_write(enc.as_slice(), offset as u64 + 20)?;

                self.set_path(
                    to,
                    Create(VfsEntry::File(VfsFile::new(offset, len, nonce, text.len(), date_time, checksum)))
                )?;

                if len < key {
                    self.root.free.insert(key - len, offset + len);
                }
            },

            None => {
                let len = self.seek_write(enc.as_slice(), self.root.cur_offset as u64 + 20)?;

                self.set_path(
                    to,
                    Create(
                        VfsEntry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce,
                                text.len(),
                                date_time,
                                checksum
                            )
                        )
                    )
                )?;

                self.root.cur_offset += len;
            }
        };

        OK
    }

    pub fn export(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(from.clone())?;

        if let VfsEntry::File(vfs_file) = entry {
            let buf = self.read_encrypted(vfs_file.length, vfs_file.offset as u64, vfs_file.nonce)?;

            let mut file = File::create(to)?;
            file.write_all(&buf)?;
        } else {
            return Err(format!("{from} is not a file").into());
        }

        OK
    }

    pub fn nano(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            VfsEntry::File(file) => file,
            VfsEntry::Directory(_) => return Err(format!("`{path}` is not a file.").into())
        };

        let mut text = String::new();
        let mut line = scan!(".. ", self)?;

        while !line.trim_end().ends_with("<< EOF") {
            text.push_str(line.as_str());
            line = scan!(".. ", self)?;
        }

        line = line.trim_end().to_string();

        text.push_str(&line[..(line.len() - 6)]);

        let nonce: [u8; 12] = rand::random();

        let enc = self.encrypt(text.as_bytes(), nonce)?;
        let date_time = datetime::now();

        let len = enc.len();

        self.hasher.update(&enc);
        let checksum = self.hasher.finalize_reset().to_vec();

        match len.cmp(&file.length) {
            Ordering::Equal => {
                self.seek_write(enc.as_slice(), file.offset as u64 + 20)?;

                self.set_path(path, Update(VfsEntry::File(VfsFile { nonce, date_time, checksum, ..file })))
            },

            Ordering::Less => {
                self.seek_write(enc.as_slice(), file.offset as u64 + 20)?;

                self.set_path(path, Update(VfsEntry::File(VfsFile::new(file.offset, len, nonce, text.len(), date_time, checksum))))?;

                let mut buf = vec![0; file.length - len];
                self.seek_write(&mut buf, file.offset as u64 - len as u64 + 20)?;

                self.root.free.insert(len - file.length, len);
                OK
            },

            Ordering::Greater => {
                self.root.free.insert(file.length, file.offset);
                self.seek_write(vec![0; file.length].as_slice(), file.offset as u64 + 20)?;

                self.seek_write(enc.as_slice(), self.root.cur_offset as u64 + 20)?;
                self.root.cur_offset += len;

                self.set_path(
                    path,
                    Update(
                        VfsEntry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce,
                                text.len(),
                                date_time,
                                checksum
                            )
                        )
                    )
                )
            }
        }
    }

    pub fn help() -> Result<(), Box<dyn Error>> {
        Ok(println!("{}", format!(r#"Very Fast and Secure file system.
Version: {}
By: Blood Rogue (github.com/blood-rogue)

Usage: {} [command] [..options]

Commands:
    ls:
		format: ls
		description: List all the entries in the current working directory.

    rm:
		format: rm [file]
		description: Remove a file with the path specified.

    cd:
		format: cd [folder]
		description: Change the current working directory to the path specified.

    cp:
		format: cp [from] [to]
		description: Copy a file from one location to another.

    mv:
		format: mv [from] [to]
		description: Moves a file from one path to another.
                      Can also be used to rename

    pwd:
		format: pwd
		description: Prints the current working directory.

    cat:
		format: cat [file]
		description: Prints the contents of a file to the console.

    help:
		format: help
		description: Prints this message to the console.

    exit:
		format: exit
		description: Writes metadata, closes the file and exits the application

    nano:
		format: nano [file]
		description: Edits the contents of the file with the given path.

    reset:
		format: reset
		description: Resets the metadata, zeroes all data and exits.

    touch:
		format: touch [file]
		description: Creates a file and opens write mode to type your contents.
                     End the stream by typeing `<< EOF`.

    mkdir:
		format: mkdir [dir_path]
		description: Create a dir at the given path with the last item being the dir name

    rmdir:
		format: rmdir [dir_path]
		description: Removes a directory recursively.

    import:
		format: import [from] [to]
		description: Imports a file from the device and adds it to the Vfs.

    export:
		format: export [from] [to]
		description: Exports a decrypted file from Vfs to the device.

    check:
		format: check
		description: Checks the integrity of the stored files.

    defrag:
		format: defrag
		description: Defragments the Vfs and removes the free areas in between.
        note: Currently this feature is not yet implemented.
              Expected to be implemented by v3.2.0
"#, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")).green()))
    }

    pub fn check(&mut self) -> Result<(), Box<dyn Error>> {
        let dir = match self.get_path("".to_string()) {
            Ok(p) => match p {
                VfsEntry::File(_) => return Err("Current directory is a file which should not be possible.\n\tPlease raise an issue at github.com/blood-rogue/vfs/issues".into()),
                VfsEntry::Directory(dir) => dir
            },
            Err(err) => return Err(format!("Error while getting working directory: {}", err).into())
        };

        self.check_dir(dir, self.make_path("".to_string()).join("/"))
    }
}
