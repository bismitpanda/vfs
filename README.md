# VFS (*V*ery *F*ast and *S*ecure)

Vfs is a virtual file system (it's also *vfs*) that exposes a linux like console and supports most of the common commands.
It stores the files in encrypted and compressed format.

## Features
- Linux like commands.
- Encrypted with `aes-256-gcm` with key provided by user.
- Compressed using [`snappy`](https://github.com/BurntSushi/rust-snappy) compression algorithm.
- SHA-1 checksums to check file integrity.

## File format (*.vfs)
| Offset | Hex | Description |
| ------ | --- | ----------- 
| 0 | `76 66 73 00` | The magic bytes `vfs\0` |
| 4 | `00 00 00 00 00 00 00 00` | The length of the meta-data |
| 12 | `00 00 00 00 00 00 00 00` | The offset of the meta-data |

**Note**: The hex bytes for offsets 4 and 12 are an example and are not fixed. They depend on the contents stored in the file system.

## Supported Commands

- #### `ls`:
    - **usage**: `ls`
    - **description**: List all the entries in the current working directory.

- #### `rm`:
    - **usage**: `rm <file_path>`
    - **description**: Remove a file with the path specified.

- #### `cd`:
    - **usage**: `cd <folder_path>`
    - **description**: Change the current working directory to the path specified.

- #### `cp`:
    - **usage**: `cp <from> <to>`
    - **description**: Copy a file from one location to another.

- #### `mv`:
    - **usage**: `mv <from> <to>`
    - **description**: Moves a file from one path to another.
                    Can also be used to rename

- #### `pwd`:
    - **usage**: `pwd`
    - **description**: Prints the current working directory.

- #### `cat`:
    - **usage**: `cat <file_path>`
    - **description**: Prints the contents of a file to the console.

- #### `help`:
    - **usage**: `help`
    - **description**: Prints this message to the console.

- #### `exit`:
    - **usage**: `exit`
    - **description**: Writes metadata, closes the file and exits the application

- #### `nano`:
    - **usage**: `nano <file_path>`
    - **description**: Edits the contents of the file with the given path.

- #### `reset`:
    - **usage**: `reset`
    - **description**: Resets the metadata, zeroes all data and exits.

- #### `touch`:
    - **usage**: `touch <file_path>`
    - **description**: Creates a file and opens write mode to type your contents.
                    End the stream by typeing `<< EOF`.

- #### `mkdir`:
    - **usage**: `mkdir <dir_path>`
    - **description**: Create a dir at the given path with the last item being the dir name

- #### `rmdir`:
    - **usage**: `rmdir <dir_path>`
    - **description**: Removes a directory recursively.

- #### `import`:
    - **usage**: `import <from> <to>`
    - **description**: Imports a file from the device and adds it to the Vfs.

- #### `export`:
    - **usage**: `export <from> <to>`
    - **description**: Exports a decrypted file from Vfs to the device.

- #### `check`:
    - **usage**: `check`
    - **description**: Checks the integrity of the stored files.

- #### `defrag`:
    - **usage**: `defrag`
    - **description**: Defragments the Vfs and removes the free areas in between.
    - **note**: *Currently this feature is not yet implemented.
             Expected to be implemented by v3.1.0*