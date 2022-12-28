use std::io::Write;
mod datetime;
use crate::datetime::VfsDateTime;

mod commands;
use crate::commands::Commands;

mod vfs;
use vfs::Vfs;

fn main() {
    let mut vfs = Vfs::new("test.vfs".to_string());
    if let Err(err) = vfs.init() {
        return println!("{err}");
    };

    let err = loop {
        let cmd = scan!(">> ");
        let cmds: Vec<String> = cmd.trim_end().split(' ').map(String::from).collect();
        let res = match Commands::from(cmds[0].clone()) {
            Commands::LS => vfs.ls(),
            Commands::PWD => vfs.pwd(),
            Commands::HELP => Vfs::help(),
            Commands::EXIT => break vfs.exit(),
            Commands::RESET => break vfs.reset(),
            Commands::DEFRAG => Err("Not implemented".into()),

            Commands::RM => if cmds.len() == 2 {
                vfs.rm(cmds[1].clone())
            } else {
                Err(format!("Usage: rm [path]").into())
            },

            Commands::CD => if cmds.len() == 2 {
                vfs.cd(cmds[1].clone())
            } else {
                Err(format!("Usage: cd [path]").into())
            },

            Commands::CAT => if cmds.len() == 2 {
                vfs.cat(cmds[1].clone())
            } else {
                Err(format!("Usage: cat [path]").into())
            },

            Commands::NANO => if cmds.len() == 2 {
                vfs.nano(cmds[1].clone())
            } else {
                Err(format!("Usage: nano [path]").into())
            },

            Commands::TOUCH => if cmds.len() == 2 {
                vfs.touch(cmds[1].clone())
            } else {
                Err(format!("Usage: touch [path]").into())
            },

            Commands::MKDIR => if cmds.len() == 2 {
                vfs.mkdir(cmds[1].clone())
            } else {
                Err(format!("Usage: mkdir [path]").into())
            },

            Commands::RMDIR => if cmds.len() == 2 {
                vfs.rmdir(cmds[1].clone())
            } else {
                Err(format!("Usage: rmdir [path]").into())
            },

            Commands::CP => if cmds.len() == 3 {
                vfs.cp(cmds[1].clone(), cmds[2].clone())
            } else {
                Err(format!("Usage: cp [from] [to]").into())
            },

            Commands::MV => if cmds.len() == 3 {
                vfs.mv(cmds[1].clone(), cmds[2].clone())
            } else {
                Err(format!("Usage: mv [from] [to]").into())
            },

            Commands::IMPORT => if cmds.len() == 3 {
                vfs.import(cmds[1].clone(), cmds[2].clone())
            } else {
                Err(format!("Usage: import [from] [to]").into())
            },

            Commands::EXPORT => if cmds.len() == 3 {
                vfs.export(cmds[1].clone(), cmds[2].clone())
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