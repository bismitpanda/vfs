# VFS (***V***ery ***F***ast and ***S***ecure)

Vfs is a virtual file system (it's also *vfs*) that exposes a linux like console and supports most of the common commands. It stores the files in encrypted and compressed format.

## Features
- Linux like console
- Encrypted with `aes-256-gcm` with key provided by user
- Compressed using `snappy` compression algorithm

## Supported Commands

- ### `ls`:
    - **format**: `ls`
    - **description**: List all the entries in the current working directory.

- ### `rm`:
    - **format**: `rm <file_path>`
    - **description**: Remove a file with the path specified.

- ### `cd`:
    - **format**: `cd <folder_path>`
    - **description**: Change the current working directory to the path specified.

- ### `cp`:
    - **format**: `cp <from> <to>`
    - **description**: Copy a file from one location to another.

- ### `mv`:
    - **format**: `mv <from> <to>`
    - **description**: Moves a file from one path to another.
                    Can also be used to rename

- ### `pwd`:
    - **format**: `pwd`
    - **description**: Prints the current working directory.

- ### `cat`:
    - **format**: `cat <file_path>`
    - **description**: Prints the contents of a file to the console.

- ### `help`:
    - **format**: `help`
    - **description**: Prints this message to the console.

- ### `exit`:
    - **format**: `exit`
    - **description**: Writes metadata, closes the file and exits the application

- ### `nano`:
    - **format**: `nano <file_path>`
    - **description**: Edits the contents of the file with the given path.

- ### `reset`:
    - **format**: `reset`
    - **description**: Resets the metadata, zeroes all data and exits.

- ### `touch`:
    - **format**: `touch <file_path>`
    - **description**: Creates a file and opens write mode to type your contents.
                    End the stream by typeing `<< EOF`.

- ### `mkdir`:
    - **format**: `mkdir <dir_path>`
    - **description**: Create a dir at the given path with the last item being the dir name

- ### `rmdir`:
    - **format**: `rmdir <dir_path>`
    - **description**: Removes a directory recursively.

- ### `import`:
    - **format**: `import <from> <to>`
    - **description**: Imports a file from the device and adds it to the Vfs.

- ### `export`:
    - **format**: `export <from> <to>`
    - **description**: Exports a decrypted file from Vfs to the device.

- ### `defrag`:
    - **format**: `defrag`
    - **description**: Defragments the Vfs and removes the free areas in between.
    - **note**: *Currently this feature is not yet implemented.
             Expected to be implemented by v2.5.0*