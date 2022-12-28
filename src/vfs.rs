use crate::VfsDateTime;

use std::{
    io::{Write, Read},
    fs::{File, OpenOptions},
    os::windows::prelude::FileExt,
    error::Error,
    collections::{HashMap, BTreeMap, hash_map::Entry::{Occupied, Vacant}},
    cmp::Ordering,
    path::{PathBuf, Path, Component}
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    AesGcm,
    aes::Aes256,
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
use typenum::{U12, U32};
use bytecheck::CheckBytes;

#[macro_export]
macro_rules! scan {
    ($var:expr) => {{
        print!("{}", $var);
        if let Err(err) = std::io::stdout().flush() {
            panic!("{err}");
        };
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        line
    }}
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive_attr(derive(CheckBytes))]
struct VfsFile {
    offset: usize,
    length: usize,
    display_length: usize,
    date_time: u32,
    nonce: [u8; 12]
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive_attr(derive(CheckBytes))]
enum Entry {
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
    entries: HashMap<String, Entry>
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(bound(serialize = "__S: rkyv::ser::ScratchSpace + rkyv::ser::Serializer"))]
#[archive_attr(derive(CheckBytes),check_bytes(bound = "__C: rkyv::validation::ArchiveContext, <__C as rkyv::Fallible>::Error: std::error::Error"))]
struct Root {
    cur_offset: usize,
    #[omit_bounds]
    #[archive_attr(omit_bounds)]
    entries: HashMap<String, Entry>,
    free: BTreeMap<usize, usize>
}

pub struct Vfs {
    oracle: AesGcm<Aes256, U12>,
    encoder: Encoder,
    decoder: Decoder,
    root: Root,
    file: File,
    cur_directory: PathBuf
}

impl VfsFile {
    fn new(offset: usize, length: usize, nonce: [u8; 12], display_length: usize, date_time: u32) -> Self {
        Self {
            offset,
            length,
            display_length,
            nonce,
            date_time
        }
    }
}

impl VfsDirectory {
    fn new(entries: HashMap<String, Entry>, date_time: u32) -> Self {
        Self { entries, date_time }
    }

    fn default() -> Self {
        Self::new(HashMap::new(), 0)
    }
}

impl Default for Root {
    fn default() -> Self {
        Root {
            cur_offset: 0,
            entries: HashMap::from([
                (r"\".to_string(), Entry::Directory(VfsDirectory::default()))
            ]),
            free: BTreeMap::new()
        }
    }
}

fn get_key() -> GenericArray<u8, U32> {
    let key = rpassword::prompt_password("Your key: ").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());

    let cipher_key = hasher.finalize();

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
            Component::RootDir => {
                ret.push(component.as_os_str());
            },
            Component::ParentDir => {
                ret.pop();
            },
            Component::Normal(c) => {
                ret.push(c);
            },
            _ => {}
        }
    }
    ret
}

enum Action {
    Create(Entry),
    Delete,
    Update(Entry)
}

impl Vfs {
    pub fn new(path: String) -> Self {
        let cipher = Aes256Gcm::new(&get_key());
        Vfs {
            oracle: cipher,
            root: Root::default(),
            encoder: Encoder::new(),
            decoder: Decoder::new(),
            cur_directory: Path::new(r"\").join(""),
            file: OpenOptions::new().write(true).read(true).create(true).open(path).unwrap()
        }
    }

    fn get_path(&self, cur_path: String) -> Result<Entry, Box<dyn Error>> {
        let path = self.make_path(cur_path);
        let mut entry = self.root.entries[&path[0]].clone();
        for part in &path[1..] {
            match entry {
                Entry::Directory(dir) => {
                    entry = match dir.entries.get(part) {
                        Some(e) => e.clone(),
                        None => return Err(format!("Directory `{part}` not found.").into()),
                    }
                },

                Entry::File(_) => return Err(format!("`{part}` is not a directory").into())
            }
        }

        Ok(entry)
    }

    fn set_path(&mut self, cur_path: String, action: Action) -> Result<(), Box<dyn Error>> {
        let path = self.make_path(cur_path);
        let mut entry = self.root.entries.entry(path[0].clone()).or_insert(
            Entry::Directory(
                VfsDirectory::default()
            )
        );

        let (last, parts) = path[1..].split_last().unwrap();
        for part in parts {
            match entry {
                Entry::Directory(dir) => {
                    entry = match dir.entries.entry(part.clone()) {
                        Occupied(entry) => {
                            Occupied(entry).or_insert(
                                Entry::Directory(
                                    VfsDirectory::default()
                                )
                            )
                        },
                        Vacant(_) => return Err(format!("Directory `{part}` not found.").into()),
                    }
                },

                Entry::File(_) => return Err(format!("`{part}` is not a directory").into())
            }
        }

        let date_time = VfsDateTime::from_datetime();

        if let Entry::Directory(dir) = entry {
            match action {
                Action::Create(action_entry) => {
                    match dir.entries.entry(last.clone()) {
                        Occupied(_) => return Err("Entry already exists.".into()),
                        Vacant(entry) => {
                            dir.date_time = date_time.to_u32();
                            entry.insert(action_entry)
                        }
                    };
                },

                Action::Delete => {
                    match dir.entries.entry(last.clone()) {
                        Occupied( entry) => {
                            dir.date_time = date_time.to_u32();
                            entry.remove()
                        },
                        Vacant(_) => return Err("File doesn't exist.".into())
                    };
                },

                Action::Update(action_entry) => {
                    match dir.entries.entry(last.clone()) {
                        Occupied(mut entry) => {
                            dir.date_time = date_time.to_u32();
                            entry.insert(action_entry)
                        },
                        Vacant(_) => return Err("File doesn't exist.".into())
                    };
                }
            }
        }

        Ok(())
    }

    pub fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let mut meta_len_bytes= [0; 8];
        self.file.seek_read(&mut meta_len_bytes, 0)?;
        let meta_len = usize::from_ne_bytes(meta_len_bytes);

        if meta_len == 0 {
            self.root = Root::default();
            return Ok(());
        }

        let new_buf = &mut vec![u8::MIN; meta_len as usize];
        self.file.seek_read(new_buf, 8)?;

        let nonce = Nonce::from_slice(b"secure nonce");

        let decrypted_buf = match self.oracle.decrypt(&nonce, self.decoder.decompress_vec(new_buf.as_slice())?.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err("Error occured during decryption".into())
        };

        let mut aligned_vec = AlignedVec::new();
        aligned_vec.extend_from_slice(decrypted_buf.as_slice());

        self.root = rkyv::from_bytes::<Root>(&aligned_vec)?;

        Ok(())
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
            Err(_) => Err("Error occured during encryption.".into())
        }
    }

    fn compress(&mut self, buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let compressed = self.encoder.compress_vec(buf)?;
        Ok(compressed)
    }

    fn read_encrypted(&mut self, length: usize, offset: u64, nonce: [u8; 12]) -> Result<Vec<u8>, Box<dyn Error>> {
        let new_buf: &mut Vec<u8> = &mut vec![0; length];
        self.file.seek_read(new_buf, offset + HEADER_SIZE + 8)?;

        let nonce = Nonce::from_slice(&nonce);

        let decrypted_buf = match self.oracle.decrypt(&nonce, self.decoder.decompress_vec(new_buf.as_slice())?.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err("Error occured during decryption".into())
        };

        Ok(decrypted_buf)
    }
}

impl Vfs {
    pub fn exit(&mut self) -> Result<(), Box<dyn Error>> {
        const SIZE: usize = HEADER_SIZE as usize;
        let bytes = rkyv::to_bytes::<_, SIZE>(&self.root)?;
        let enc_bytes = self.encrypt(bytes.as_slice(), *b"secure nonce")?;
        let len = self.file.seek_write(&enc_bytes, 8)?;
        self.file.seek_write(&len.to_ne_bytes(), 0)?;

        Ok(())
    }

    pub fn touch(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let mut text = String::new();
        let mut line: String = scan!(".. ");

        while !line.trim_end().ends_with("<< EOF") {
            text.push_str(line.as_str());
            line = scan!(".. ");
        }

        line = line.trim_end().to_string();

        text.push_str(&line[..(line.len() - 6)]);

        let nonce: [u8; 12] = rand::random();

        let enc = self.encrypt(text.as_bytes(), nonce)?;
        let date_time = VfsDateTime::from_datetime();

        match self.root.free.iter().position(|(&len, _)| enc.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                let len = self.file.seek_write(enc.as_slice(), offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    path,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, len, nonce, text.len(), date_time.to_u32())
                        )
                    )
                )?;

                if len < key {
                    self.root.free.insert(key - len, offset + len);
                }
            },

            None => {
                let len = self.file.seek_write(enc.as_slice(), self.root.cur_offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    path,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce,
                                text.len(),
                                date_time.to_u32()
                            )
                        )
                    )
                )?;
                self.root.cur_offset += len;
            }
        };

        Ok(())
    }

    pub fn cat(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(path.clone())?;

        if let Entry::File(file) = entry {
            let buf = self.read_encrypted(file.length, file.offset as u64, file.nonce)?;
            println!("{}", String::from_utf8(buf)?);
        } else {
            return Err(format!("{path} is not a file").into());
        }

        Ok(())
    }

    pub fn cp(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(from.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{from}` is not a file.").into())
        };

        let mut buf = vec![0; file.length];

        self.file.seek_read(&mut buf, (file.offset as u64) + HEADER_SIZE + 8)?;
        let date_time = VfsDateTime::from_datetime();

        match self.root.free.iter().position(|(&len, _)| file.length <= len) {
            Some(len) => {
                let offset = self.root.free.remove(&len).unwrap();
                self.file.seek_write(&buf.as_slice(), offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, file.length, file.nonce, file.display_length, date_time.to_u32())
                        )
                    )
                )?;

                if file.length < len {
                    self.root.free.insert(len - file.length, offset + file.length);
                }
            },

            None => {
                self.file.seek_write(buf.as_slice(), (self.root.cur_offset as u64) + HEADER_SIZE + 8)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(self.root.cur_offset, file.length, file.nonce, file.display_length, date_time.to_u32())
                        )
                    )
                )?;

                self.root.cur_offset += file.offset;
            }
        }

        Ok(())
    }

    pub fn mv(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(from.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err("`mv` for directories are not currently implemented".into())
        };

        self.set_path(from, Action::Delete)?;
        self.set_path(to, Action::Create(Entry::File(file)))
    }

    pub fn rm(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{path}` is not a file. use `rmdir` instead.").into())
        };

        let mut buf = vec![0; file.length];
        self.file.seek_write(&mut buf, (file.offset as u64) + HEADER_SIZE + 8)?;

        self.set_path(path, Action::Delete)
    }

    pub fn ls(&self) -> Result<(), Box<dyn Error>> {
        let directory = match self.get_path("./".to_string())? {
            Entry::Directory(dir) => dir,
            Entry::File(_) => return Err(format!("Working directory is not a file").into())
        };

        let max = match directory.entries.keys().map(String::len).max() {
            Some(max) if max > 4 => max,
            _ => 4
        };

        let width = 23;

        println!("{:^max$}   {:^max$}   {:^max$}   {:^width$}", "Name", "Type", "Size", "Date");
        println!("{0:-<max$}   {0:-<max$}   {0:-<max$}   {0:-<width$}", "");

        for (path, entry) in &directory.entries {
            match entry {
                Entry::File(file) => println!("{path:max$}   File   {:^max$}   {:^width$}", file.display_length, VfsDateTime::from_u32(file.date_time)),
                Entry::Directory(directory) => println!("{path:max$}   Dir    {:^max$}   {:^width$}", directory.entries.len(), VfsDateTime::from_u32(directory.date_time))
            }
        }

        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), Box<dyn Error>> {
        self.root = Root::default();

        self.file.sync_all()?;
        let len = self.file.metadata()?.len();

        let buf: Vec<u8> = vec![0; len as usize];
        self.file.seek_write(buf.as_slice(), 0)?;

        Ok(())
    }

    pub fn cd(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        self.get_path(path.clone())?;
        self.cur_directory = normalize_path(&self.cur_directory.join(path).as_path());

        Ok(())
    }

    pub fn mkdir(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let date_time = VfsDateTime::from_datetime();

        self.set_path(
            path,
            Action::Create(
                Entry::Directory(
                    VfsDirectory::new(HashMap::new(), date_time.to_u32())
                )
            )
        )
    }

    pub fn pwd(&self) -> Result<(), Box<dyn Error>> {
        Ok(println!("{}", self.cur_directory.display()))
    }

    pub fn rmdir(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let dir = match self.get_path(path.clone())? {
            Entry::File(_) => return Err(format!("`{path}` is not a directory. use `rm` instead.").into()),
            Entry::Directory(dir) => dir
        };

        for (name, entry) in dir.entries {
            match entry {
                Entry::File(_) => self.rm(vec![path.clone(), name].join("/"))?,
                Entry::Directory(_) => self.rmdir(vec![path.clone(), name].join("/"))?
            }
        }

        self.set_path(path, Action::Delete)
    }

    pub fn import(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {

        let mut file = File::open(from)?;
        let text = &mut Vec::new();
        file.read_to_end(text)?;

        let nonce: [u8; 12] = rand::random();

        let enc = self.encrypt(text.as_slice(), nonce)?;
        let date_time = VfsDateTime::from_datetime();

        match self.root.free.iter().position(|(&len, _)| enc.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                let len = self.file.seek_write(enc.as_slice(), offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, len, nonce, text.len(), date_time.to_u32())
                        )
                    )
                )?;

                if len < key {
                    self.root.free.insert(key - len, offset + len);
                }
            },

            None => {
                let len = self.file.seek_write(enc.as_slice(), self.root.cur_offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce,
                                text.len(),
                                date_time.to_u32()
                            )
                        )
                    )
                )?;
                self.root.cur_offset += len;
            }
        };

        Ok(())
    }

    pub fn export(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(from.clone())?;

        if let Entry::File(vfs_file) = entry {
            let buf = self.read_encrypted(vfs_file.length, vfs_file.offset as u64, vfs_file.nonce)?;

            let mut file = File::create(to)?;
            file.write_all(&buf)?;
        } else {
            return Err(format!("{from} is not a file").into());
        }

        Ok(())
    }

    pub fn nano(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{path}` is not a file.").into())
        };

        let mut text = String::new();
        let mut line: String = scan!(".. ");

        while !line.trim_end().ends_with("<< EOF") {
            text.push_str(line.as_str());
            line = scan!(".. ");
        }

        line = line.trim_end().to_string();

        text.push_str(&line[..(line.len() - 6)]);

        let nonce: [u8; 12] = rand::random();

        let enc = self.encrypt(text.as_bytes(), nonce)?;
        let date_time = VfsDateTime::from_datetime();

        let len = enc.len();

        match len.cmp(&file.length) {
            Ordering::Equal => {
                self.file.seek_write(enc.as_slice(), file.offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(file.offset, file.length, nonce, file.display_length, date_time.to_u32())
                        )
                    )
                )
            },

            Ordering::Less => {
                self.file.seek_write(enc.as_slice(), file.offset as u64 + HEADER_SIZE + 8)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(file.offset, len, nonce, text.len(), date_time.to_u32())
                        )
                    )
                )?;

                let mut buf = vec![0; file.length - len];
                self.file.seek_write(&mut buf, file.offset as u64 - len as u64 + HEADER_SIZE + 8)?;

                self.root.free.insert(len - file.length, len);
                Ok(())
            },

            Ordering::Greater => {
                self.root.free.insert(file.length, file.offset);
                self.file.seek_write(vec![0; file.length].as_slice(), file.offset as u64 + HEADER_SIZE + 8)?;

                self.file.seek_write(enc.as_slice(), self.root.cur_offset as u64 + HEADER_SIZE + 8)?;
                self.root.cur_offset += len;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce,
                                text.len(),
                                date_time.to_u32()
                            )
                        )
                    )
                )
            }
        }
    }

    pub fn help() -> Result<(), Box<dyn Error>> {
        Ok(println!(r#"Very Fast and Secure file system.
Version: 2.3.4
By: Blood Rogue (github.com/blood-rogue)

Usage: [command] [..options]

Commands:
    ls:
        format - ls
        description - List all the entries in the current working directory.

    rm:
        format - rm [file_path]
        description - Remove a file with the path specified.

    cd:
        format - cd [folder_path]
        description - Change the current working directory to the path specified.

    cp:
        format - cp [from] [to]
        description - Copy a file from one location to another.

    mv:
        format - mv [from] [to]
        description - Moves a file from one path to another.
                      Can also be used to rename

    pwd:
        format - pwd
        description - Prints the current working directory.

    cat:
        format - cat [file_path]
        description - Prints the contents of a file to the console.

    help:
        format - help
        description - Prints this message to the console.

    exit:
        format - exit
        description - Writes metadata, closes the file and exits the application

    nano:
        format - nano [file_path]
        description - Edits the contents of the file with the given path.

    reset:
        format - reset
        description - Resets the metadata, zeroes all data and exits.

    touch:
        format - touch [file_path]
        description - Creates a file and opens write mode to type your contents.
                      End the stream by typeing `<< EOF`.

    mkdir:
        format - mkdir [dir_path]
        description - Create a dir at the given path with the last item being the dir name

    rmdir:
        format - rmdir [dir_path]
        description - Removes a directory recursively.

    import:
        format - import [from] [to]
        description - Imports a file from the device and adds it to the Vfs.

    export:
        format - export [from] [to]
        description - Exports a decrypted file from Vfs to the device.

    defrag:
        format - defrag
        description - Defragments the Vfs and removes the free areas in between.
        note - Currently this feature is not yet implemented.
               Expected to be implemented by v2.5.0
"#))
    }
}

const HEADER_SIZE: u64 = 524288;