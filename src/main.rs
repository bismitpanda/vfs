use std::{
    io::{Write, Read},
    fs::{
        File,
        OpenOptions
    },
    os::windows::prelude::FileExt,
    error::Error,
    collections::{
        HashMap,
        BTreeMap,
        hash_map::Entry as HashMapEntry
    },
    cmp::Ordering,
    path::{
        PathBuf,
        Path,
        Component
    }
};

use aes_gcm::{
    aead::{
        Aead,
        KeyInit,
        Error as AeadError
    },
    Aes256Gcm,
    AesGcm,
    aes::Aes256, Nonce
};

use rkyv::{
    Archive,
    Deserialize,
    Serialize,
    AlignedVec
};

use sha2::{
    Sha256,
    Digest
};

use generic_array::GenericArray;
use typenum::{U12, U32};
use bytecheck::CheckBytes;
use hex::{encode, decode};

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
    offset: u32,
    length: usize,
    nonce: [u8; 12]
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive_attr(derive(CheckBytes))]
enum Entry {
    File(VfsFile),
    Directory(VfsDirectory)
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive(
    bound(
        serialize = "__S: rkyv::ser::ScratchSpace + rkyv::ser::Serializer"
    )
)]
#[archive_attr(
    derive(CheckBytes),
    check_bytes(
        bound = "__C: rkyv::validation::ArchiveContext, <__C as rkyv::Fallible>::Error: std::error::Error"
    )
)]
struct VfsDirectory {
    #[omit_bounds]
    #[archive_attr(omit_bounds)]
    entries: HashMap<String, Entry>
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(
    bound(
        serialize = "__S: rkyv::ser::ScratchSpace + rkyv::ser::Serializer"
    )
)]
#[archive_attr(
    derive(CheckBytes),
    check_bytes(
        bound = "__C: rkyv::validation::ArchiveContext, <__C as rkyv::Fallible>::Error: std::error::Error"
    )
)]
struct Root {
    cur_offset: u32,
    #[omit_bounds]
    #[archive_attr(omit_bounds)]
    entries: HashMap<String, Entry>,
    free: BTreeMap<usize, u32>
}

struct Vfs {
    oracle: AesGcm<Aes256, U12>,
    root: Root,
    file: File,
    cur_directory: PathBuf
}

#[derive(PartialEq, Eq)]
enum Commands {
    EXIT,
    TOUCH,
    CAT,
    NANO,
    CP,
    MV,
    RM,
    LS,
    RESET,
    CD,
    MKDIR,
    PWD,
    RMDIR,
    IMPORT,
    EXPORT,
    DEFRAG,
    HELP,
    ENCRYPT,
    DECRYPT,
    INVALID,
}

impl From<String> for Commands {
    fn from(cmd: String) -> Self {
        match cmd.as_str() {
            "exit" | "ext" | "e" => Commands::EXIT,
            "touch" | "tch" => Commands::TOUCH,
            "cat" => Commands::CAT,
            "nano" | "nn" => Commands::NANO,
            "cp" => Commands::CP,
            "mv" => Commands::MV,
            "rm" => Commands::RM,
            "ls" => Commands::LS,
            "reset" |"rst" => Commands::RESET,
            "cd" => Commands::CD,
            "mkdir" => Commands::MKDIR,
            "pwd" => Commands::PWD,
            "rmdir" => Commands::RMDIR,
            "import" | "imp" => Commands::IMPORT,
            "export" | "exp" => Commands::EXPORT,
            "defrag" | "dfrg" => Commands::DEFRAG,
            "help" | "hlp" | "h" => Commands::HELP,
            "encrypt" | "enc" => Commands::ENCRYPT,
            "decrypt" | "dec" => Commands::DECRYPT,
            _ => Commands::INVALID
        }
    }
}

impl VfsFile {
    fn new(offset: u32, length: usize, nonce: [u8; 12]) -> Self {
        Self {
            offset,
            length,
            nonce
        }
    }
}

impl Default for VfsFile {
    fn default() -> Self {
        Self::new(0, 0, [0; 12])
    }
}

impl VfsDirectory {
    fn new(entries: HashMap<String, Entry>) -> Self {
        Self { entries }
    }
}

impl Default for VfsDirectory {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}

impl Default for Root {
    fn default() -> Self {
        Root {
            cur_offset: 0,
            entries: HashMap::from([
                ("\\".to_string(), Entry::Directory(VfsDirectory::default()))
            ]),
            free: BTreeMap::new()
        }
    }
}

#[inline]
fn get_key() -> GenericArray<u8, U32> {
    let key = rpassword::prompt_password("Your key: ").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());

    let cipher_key = hasher.finalize();

    return cipher_key;
}

#[inline(always)]
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
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
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
    fn new(path: String) -> Self {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(get_key().as_slice()));
        Vfs {
            root: Root::default(),
            file: OpenOptions::new().write(true).read(true).create(true).open(path).unwrap(),
            oracle: cipher,
            cur_directory: Path::new(r"\").join("")
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
                        HashMapEntry::Occupied(entry) => {
                            HashMapEntry::Occupied(entry).or_insert(
                                Entry::Directory(
                                    VfsDirectory::default()
                                )
                            )
                        },

                        HashMapEntry::Vacant(_) => return Err(format!("Directory `{part}` not found.").into()),
                    }
                },

                Entry::File(_) => return Err(format!("`{part}` is not a directory").into())
            }
        }

        match action {
            Action::Create(action_entry) => {
                if let Entry::Directory(dir) = entry {
                    match dir.entries.entry(last.clone()) {
                        HashMapEntry::Occupied(_) => return Err("File already exists.".into()),
                        HashMapEntry::Vacant(entry) => entry.insert(action_entry)
                    };
                }
            },

            Action::Delete => {
                if let Entry::Directory(dir) = entry {
                    match dir.entries.entry(last.clone()) {
                        HashMapEntry::Occupied( entry) => entry.remove(),
                        HashMapEntry::Vacant(_) => return Err("File doesn't exist.".into())
                    };
                }
            },

            Action::Update(action_entry) => {
                if let Entry::Directory(dir) = entry {
                    match dir.entries.entry(last.clone()) {
                        HashMapEntry::Occupied(mut entry) => entry.insert(action_entry),
                        HashMapEntry::Vacant(_) => return Err("File doesn't exist.".into())
                    };
                }
            }
        }
        Ok(())
    }

    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let mut meta_len_bytes= [0; 4];
        self.file.seek_read(&mut meta_len_bytes, 0)?;
        let meta_len = u32::from_ne_bytes(meta_len_bytes);

        let mut buf = [0; HEADER_SIZE as usize];
        self.file.seek_read(&mut buf, 4)?;

        if meta_len == 0 {
            self.root = Root::default();
            return Ok(());
        }

        let mut aligned_vec = AlignedVec::new();
        aligned_vec.extend_from_slice(&buf[..(meta_len as usize)]);

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

    fn encrypt_data(&self, buf: &[u8], nonce: [u8; 12]) -> Result<Vec<u8>, AeadError> {
        self.oracle.encrypt(&Nonce::from_slice(&nonce), buf)
    }

    fn read_encrypted(&self, length: usize, offset: u64, nonce: [u8; 12]) -> Result<Vec<u8>, Box<dyn Error>> {
        let new_buf: &mut Vec<u8> = &mut vec![0; length];
        self.file.seek_read(new_buf, offset + HEADER_SIZE + 4)?;

        let nonce = Nonce::from_slice(&nonce);

        let decrypted_buf = match self.oracle.decrypt(&nonce, new_buf.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err("Error occured while decryption".into())
        };

        Ok(decrypted_buf)
    }
}

impl Vfs {
    fn exit(&self) -> Result<(), Box<dyn Error>> {
        const SIZE: usize = HEADER_SIZE as usize;
        let bytes = rkyv::to_bytes::<_, SIZE>(&self.root)?;
        self.file.seek_write(&(bytes.len() as u32).to_ne_bytes(), 0)?;
        self.file.seek_write(&bytes, 4)?;

        Ok(())
    }

    fn touch(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let mut text = String::new();
        let mut line: String = scan!(".. ");

        while !line.trim_end().ends_with("<< EOF") {
            text.push_str(line.as_str());
            line = scan!(".. ");
        }

        line = line.trim_end().to_string();

        text.push_str(&line[..(line.len() - 6)]);

        let nonce: [u8; 12] = rand::random();

        let enc = match self.encrypt_data(text.as_bytes(), nonce) {
            Ok(v) => v,
            Err(_) => return Err("Error occured while encryption.".into())
        };

        match self.root.free.iter().position(|(&len, _)| enc.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                let len = self.file.seek_write(enc.as_slice(), offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, len, nonce)
                        )
                    )
                )?;

                if len < key {
                    self.root.free.insert(key - len, offset + len as u32);
                }
            },

            None => {
                let len = self.file.seek_write(enc.as_slice(), self.root.cur_offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce
                            )
                        )
                    )
                )?;
                self.root.cur_offset += len as u32;
            }
        };

        Ok(())
    }

    fn cat(&self, path: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(path.clone())?;

        if let Entry::File(file) = entry {
            let buf = self.read_encrypted(file.length, file.offset as u64, file.nonce)?;
            println!("{}", String::from_utf8(buf)?);
        } else {
            return Err(format!("{path} is not a file").into());
        }

        Ok(())
    }

    fn cp(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(from.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{from}` is not a file.").into())
        };

        let mut buf = vec![0; file.length];

        self.file.seek_read(&mut buf, (file.offset as u64) + HEADER_SIZE + 4)?;
        let nonce: [u8; 12] = rand::random();

        match self.root.free.iter().position(|(&len, _)| file.length <= len) {
            Some(len) => {
                let offset = self.root.free.remove(&len).unwrap();
                self.file.seek_write(&buf.as_slice(), offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, file.length, nonce)
                        )
                    )
                )?;

                if file.length < len {
                    self.root.free.insert(len - file.length, offset + file.length as u32);
                }
            },

            None => {
                self.file.seek_write(buf.as_slice(), (self.root.cur_offset as u64) + 4 + HEADER_SIZE)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(self.root.cur_offset, file.length, nonce)
                        )
                    )
                )?;

                self.root.cur_offset += file.offset;
            }
        }

        Ok(())
    }

    fn mv(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(from.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err("`mv` for directories are not currently implemented".into())
        };

        self.set_path(from, Action::Delete)?;
        self.set_path(to, Action::Create(Entry::File(file)))
    }

    fn rm(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{path}` is not a file. use `rmdir` instead.").into())
        };

        let mut buf = vec![0; file.length];
        self.file.seek_write(&mut buf, (file.offset as u64) + HEADER_SIZE + 4)?;

        self.set_path(path, Action::Delete)
    }

    fn ls(&self) -> Result<(), Box<dyn Error>> {
        let directory = match self.get_path("./".to_string())? {
            Entry::Directory(dir) => dir,
            Entry::File(_) => return Err(format!("Working directory is not a file").into())
        };

        let max = match directory.entries.keys().map(String::len).max() {
            Some(max) if max > 4 => max,
            _ => 4
        };

        println!("{:^max$}   {:^max$}   {:^max$}", "Name", "Type", "Size");
        println!("{0:-<max$}   {0:-<max$}   {0:-<max$}", "");

        for (path, entry) in &directory.entries {
            match entry {
                Entry::File(file) => println!("{path:max$}   {:^max$}   {:^max$}", "File", file.length),
                Entry::Directory(directory) => println!("{path:max$}   {:^max$}   {:^max$}", "Dir", directory.entries.len())
            }
        }

        Ok(())
    }

    fn reset(&mut self) -> Result<(), Box<dyn Error>> {
        self.root = Root::default();

        self.file.sync_all()?;
        let len = self.file.metadata()?.len();

        let buf: Vec<u8> = vec![0; len as usize];
        self.file.seek_write(buf.as_slice(), 0)?;

        Ok(())
    }

    fn cd(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        self.get_path(path.clone())?;
        self.cur_directory = normalize_path(&self.cur_directory.join(path).as_path());

        Ok(())
    }

    fn mkdir(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        self.set_path(
            path,
            Action::Create(
                Entry::Directory(
                    VfsDirectory::default()
                )
            )
        )
    }

    fn pwd(&self) -> Result<(), Box<dyn Error>> {
        Ok(println!("{}", self.cur_directory.display()))
    }

    fn rmdir(&mut self, path: String) -> Result<(), Box<dyn Error>> {
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

    fn import(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {

        let mut file = File::open(from)?;
        let text = &mut String::new();
        file.read_to_string(text)?;

        let nonce: [u8; 12] = rand::random();

        let enc = match self.encrypt_data(text.as_bytes(), nonce) {
            Ok(v) => v,
            Err(_) => return Err("Error occured during encryption".into())
        };

        match self.root.free.iter().position(|(&len, _)| enc.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                let len = self.file.seek_write(enc.as_slice(), offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, len, nonce)
                        )
                    )
                )?;

                if len < key {
                    self.root.free.insert(key - len, offset + len as u32);
                }
            },

            None => {
                let len = self.file.seek_write(enc.as_slice(), self.root.cur_offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce
                            )
                        )
                    )
                )?;
                self.root.cur_offset += len as u32;
            }
        };

        Ok(())
    }

    fn export(&self, from: String, to: String) -> Result<(), Box<dyn Error>> {
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

    fn nano(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{path}` is not a file.").into())
        };

        let mut text = String::new();
        let mut line: String = scan!(".. ");

        while line.trim_end() != "<< EOF" {
            text.push_str(line.as_str());
            line = scan!(".. ");
        }

        let nonce: [u8; 12] = rand::random();

        let enc = match self.encrypt_data(text.as_bytes(), nonce) {
            Ok(v) => v,
            Err(_) => return Err("Error occured during encryption".into())
        };

        match enc.len().cmp(&file.length) {
            Ordering::Equal => {
                self.file.seek_write(enc.as_slice(), file.offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(VfsFile { nonce, ..file })
                    )
                )
            },

            Ordering::Less => {
                let len = self.file.seek_write(enc.as_slice(), file.offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(file.offset, len, nonce)
                        )
                    )
                )?;

                let mut buf = vec![0; file.length - len];
                self.file.seek_write(&mut buf, file.offset as u64 + len as u64)?;

                self.root.free.insert(len - file.length, len as u32);
                Ok(())
            },

            Ordering::Greater => {
                self.root.free.insert(file.length, file.offset);

                let len = self.file.seek_write(enc.as_slice(), self.root.cur_offset as u64 + HEADER_SIZE + 4)?;
                self.root.cur_offset += len as u32;

                let empty_bytes = vec![0; file.length];
                self.file.seek_write(empty_bytes.as_slice(), file.offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                len,
                                nonce
                            )
                        )
                    )
                )
            }
        }
    }

    fn help() -> Result<(), Box<dyn Error>> {
        Ok(println!(r#"Very Fast and Secure file system.
Version: 2.0.0
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
    
    encrypt:
        format - encrypt
        description - A test command to check encryption.
                      It encrypts using nonce=`unique nonce`.
"#))
    } 

    fn encrypt(&self) -> Result<(), Box<dyn Error>> {
        let text = scan!(".. ");
        let nonce = Nonce::from_slice(b"unique nonce");
        let enc = self.oracle.encrypt(&nonce, text.as_bytes()).unwrap();
        Ok(println!("{}", encode(enc)))
    }

    fn decrypt(&self) -> Result<(), Box<dyn Error>> {
        let text = scan!(".. ");
        let nonce = Nonce::from_slice(b"unique nonce");
        let dec = self.oracle.decrypt(&nonce, decode(text.trim_end())?.as_slice()).unwrap();
        Ok(println!("{}", String::from_utf8(dec)?))
    }
}

const HEADER_SIZE: u64 = 524288;

fn get(lst: &Vec<String>, idx: usize) -> String {
    match lst.get(idx) {
        Some(s) => s.clone(),
        None => String::new()
    }
}

fn main() {
    let mut vfs = Vfs::new("test.vfs".to_string());
    if let Err(err) = vfs.init() {
        println!("{err}")
    };

    let err = loop {
        let cmd = scan!(">> ");
        let cmds: Vec<String> = cmd.trim_end().split(' ').map(String::from).collect();
        let res = match Commands::from(get(&cmds, 0)) {
            Commands::LS => vfs.ls(),
            Commands::PWD => vfs.pwd(),
            Commands::HELP => Vfs::help(),
            Commands::ENCRYPT => vfs.encrypt(),
            Commands::DECRYPT => vfs.decrypt(),
            Commands::EXIT => break vfs.exit(),
            Commands::RESET => break vfs.reset(),
            Commands::DEFRAG => Err("Not implemented".into()),

            Commands::RM => if cmds.len() == 2 {
                vfs.rm(get(&cmds, 1))
            } else {
                Err(format!("Usage: rm [path]").into())
            },

            Commands::CD => if cmds.len() == 2 {
                vfs.cd(get(&cmds, 1))
            } else {
                Err(format!("Usage: cd [path]").into())
            },

            Commands::CAT => if cmds.len() == 2 {
                vfs.cat(get(&cmds, 1))
            } else {
                Err(format!("Usage: cat [path]").into())
            },

            Commands::NANO => if cmds.len() == 2 {
                vfs.nano(get(&cmds, 1))
            } else {
                Err(format!("Usage: nano [path]").into())
            },

            Commands::TOUCH => if cmds.len() == 2 {
                vfs.touch(get(&cmds, 1))
            } else {
                Err(format!("Usage: touch [path]").into())
            },

            Commands::MKDIR => if cmds.len() == 2 {
                vfs.mkdir(get(&cmds, 1))
            } else {
                Err(format!("Usage: mkdir [path]").into())
            },

            Commands::RMDIR => if cmds.len() == 2 {
                vfs.rmdir(get(&cmds, 1))
            } else {
                Err(format!("Usage: rmdir [path]").into())
            },

            Commands::CP => if cmds.len() == 3 {
                vfs.cp(get(&cmds, 1), get(&cmds, 2))
            } else {
                Err(format!("Usage: cp [from] [to]").into())
            },

            Commands::MV => if cmds.len() == 3 {
                vfs.mv(get(&cmds, 1), get(&cmds, 2))
            } else {
                Err(format!("Usage: mv [from] [to]").into())
            },

            Commands::IMPORT => if cmds.len() == 3 {
                vfs.import(get(&cmds, 1), get(&cmds, 2))
            } else {
                Err(format!("Usage: import [from] [to]").into())
            },

            Commands::EXPORT => if cmds.len() == 3 {
                vfs.export(get(&cmds, 1), get(&cmds, 2))
            } else {
                Err(format!("Usage: export [from] [to]").into())
            },

            Commands::INVALID => Ok(println!("Invalid command entered `{}`", cmds[0])),
        };

        if let Err(err) = res {
            println!("An error occured:\n\t{err}")
        }
    };

    if let Err(err) = err {
        println!("Error occurred while exiting: {err}\n\tCheck entries before reusing.")
    }
}