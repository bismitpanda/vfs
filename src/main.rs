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
        KeyInit
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
    length: usize
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
    INVALID,
}

impl From<String> for Commands {
    fn from(cmd: String) -> Self {
        match cmd.as_str() {
            "exit" | "ext" => Commands::EXIT,
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
            _ => Commands::INVALID
        }
    }
}

impl VfsFile {
    fn new(offset: u32, length: usize) -> Self {
        Self {
            offset,
            length
        }
    }
}

impl Default for VfsFile {
    fn default() -> Self {
        Self::new(0, 0)
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
        self.read_file(&mut meta_len_bytes, 0)?;
        let meta_len = u32::from_ne_bytes(meta_len_bytes);

        let mut buf = [0; HEADER_SIZE as usize];
        self.read_file(&mut buf, 4)?;

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
        normalize_path(self.cur_directory.join(path).as_path())
            .iter()
            .map(|part| part.to_str().unwrap().to_string())
            .collect()
    }

    fn write_file(&self, buf: &[u8], offset: u64) -> Result<(), Box<dyn Error>> {
        let nonce = Nonce::from_slice(b"");
        let encrypted_buf = match self.oracle.encrypt(nonce, buf) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error occured while encryption: {e}").into())
        };
        self.file.seek_write(&encrypted_buf, offset)?;

        Ok(())
    }

    fn read_file(&self, buf: &mut [u8], offset: u64) -> Result<(), Box<dyn Error>> {
        let decrypted_buf: &mut Vec<u8> = &mut vec![0; buf.len()];
        self.file.seek_read(decrypted_buf, offset)?;

        buf.copy_from_slice(decrypted_buf.as_slice());

        Ok(())
    }
}

impl Vfs {
    fn exit(&self) -> Result<(), Box<dyn Error>> {
        const SIZE: usize = HEADER_SIZE as usize;
        let bytes = rkyv::to_bytes::<_, SIZE>(&self.root)?;
        self.write_file(&(bytes.len() as u32).to_ne_bytes(), 0)?;
        self.write_file(&bytes, 4)?;

        Ok(())
    }

    fn touch(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let mut text = String::new();
        let mut line: String = scan!(".. ");

        while !line.ends_with("<< EOF") {
            text.push_str(line.as_str());
            line = scan!(".. ");
        }

        text.push_str(&line[..(line.len() - 6)]);

        match self.root.free.iter().position(|(&len, _)| text.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                self.write_file(&text.as_bytes(), offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, text.len())
                        )
                    )
                )?;

                if text.len() < key {
                    self.root.free.insert(key - text.len(), offset + text.len() as u32);
                }
            },

            None => {
                self.write_file(&text.as_bytes(), self.root.cur_offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                text.len()
                            )
                        )
                    )
                )?;
                self.root.cur_offset += text.len() as u32;
            }
        };

        Ok(())
    }

    fn cat(&self, path: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(path.clone())?;

        if let Entry::File(file) = entry {
            let mut buf = vec![0; file.length];
            self.read_file(&mut buf, (file.offset as u64) + HEADER_SIZE + 4)?;
            print!("{}", String::from_utf8(buf)?);
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

        self.read_file(&mut buf, (file.offset as u64) + HEADER_SIZE + 4)?;

        match self.root.free.iter().position(|(&len, _)| file.length <= len) {
            Some(len) => {
                let offset = self.root.free.remove(&len).unwrap();
                self.write_file(&buf.as_slice(), offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, file.length)
                        )
                    )
                )?;

                if file.length < len {
                    self.root.free.insert(len - file.length, offset + file.length as u32);
                }
            },

            None => {
                self.write_file(buf.as_slice(), (self.root.cur_offset as u64) + 4 + HEADER_SIZE)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(self.root.cur_offset, file.length)
                        )
                    )
                )?;

                self.root.cur_offset += file.offset;
            }
        }

        Ok(())
    }

    fn mv(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(to)? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err("`mv` for directories are not currently implemented".into())
        };

        self.set_path(from, Action::Update(Entry::File(file)))
    }

    fn rm(&mut self, path: String) -> Result<(), Box<dyn Error>> {
        let file = match self.get_path(path.clone())? {
            Entry::File(file) => file,
            Entry::Directory(_) => return Err(format!("`{path}` is not a file. use `rmdir` instead.").into())
        };

        let mut buf = vec![0; file.length];
        self.write_file(&mut buf, (file.offset as u64) + HEADER_SIZE + 4)?;

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
        self.write_file(buf.as_slice(), 0)?;

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

        for (path, entry) in dir.entries {
            match entry {
                Entry::File(_) => self.rm(path)?,
                Entry::Directory(_) => self.rmdir(path)?
            }
        }

        self.set_path(path, Action::Delete)
    }

    fn import(&mut self, from: String, to: String) -> Result<(), Box<dyn Error>> {

        let mut file = File::open(from)?;
        let text = &mut String::new();
        file.read_to_string(text)?;

        match self.root.free.iter().position(|(&len, _)| text.len() <= len) {
            Some(key) => {
                let offset = self.root.free.remove(&key).unwrap();
                self.write_file(&text.as_bytes(), offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(offset, text.len())
                        )
                    )
                )?;

                if text.len() < key {
                    self.root.free.insert(key - text.len(), offset + text.len() as u32);
                }
            },

            None => {
                self.write_file(&text.as_bytes(), self.root.cur_offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    to,
                    Action::Create(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset,
                                text.len()
                            )
                        )
                    )
                )?;
                self.root.cur_offset += text.len() as u32;
            }
        };

        Ok(())
    }

    fn export(&self, from: String, to: String) -> Result<(), Box<dyn Error>> {
        let entry = self.get_path(from.clone())?;

        if let Entry::File(vfs_file) = entry {
            let mut buf = vec![0; vfs_file.length];
            self.read_file(&mut buf, (vfs_file.offset as u64) + HEADER_SIZE + 4)?;

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
        let mut line: String = scan!("... ");

        while line.trim_end() != "<< EOF" {
            text.push_str(line.as_str());
            line = scan!("... ");
        }

        match text.len().cmp(&file.length) {
            Ordering::Equal => {
                self.write_file(&text.as_bytes(), file.offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(file.clone())
                    )
                )
            },

            Ordering::Less => {
                self.write_file(&text.as_bytes(), file.offset as u64 + HEADER_SIZE + 4)?;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(file.offset, text.len())
                        )
                    )
                )?;

                let mut buf = vec![0; file.length];
                self.write_file(&mut buf, (file.offset as u64) + HEADER_SIZE + 4)?;

                self.root.free.insert(text.len() - file.length, text.len() as u32);
                Ok(())
            },

            Ordering::Greater => {
                self.root.free.insert(file.length, file.offset);

                self.write_file(&text.as_bytes(), self.root.cur_offset as u64 + HEADER_SIZE + 4)?;
                self.root.cur_offset += text.len() as u32;

                self.set_path(
                    path,
                    Action::Update(
                        Entry::File(
                            VfsFile::new(
                                self.root.cur_offset, text.len()
                            )
                        )
                    )
                )
            }
        }
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
            Commands::RESET => vfs.reset(),
            Commands::EXIT => break vfs.exit(),
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