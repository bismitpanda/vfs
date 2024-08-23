mod commands;
mod datetime;
mod vfs;

use commands::Commands;
use vfs::Vfs;

use colored::*;
use std::io::Write;

fn main() {
    let mut vfs = Vfs::new("test.vfs".to_string());
    if let Err(err) = vfs.init() {
        return println!("Error occured while initialisation: {err}");
    };

    let err = loop {
        let cmd = match scan!(">> ", vfs) {
            Ok(s) => s,
            Err(err) => break Err(err),
        };

        let cmds: Vec<String> = cmd.trim_end().split(' ').map(String::from).collect();
        let res = match Commands::from(cmds[0].as_str()) {
            Commands::LS => vfs.ls(),
            Commands::PWD => vfs.pwd(),
            Commands::HELP => Vfs::help(),
            Commands::EXIT => break vfs.exit(),
            Commands::RESET => break vfs.reset(),
            Commands::DEFRAG => Err("Not implemented".into()),

            Commands::RM => {
                if cmds.len() == 2 {
                    vfs.rm(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: rm [path]".cyan()).into())
                }
            }

            Commands::CD => {
                if cmds.len() == 2 {
                    vfs.cd(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: cd [path]".cyan()).into())
                }
            }

            Commands::CAT => {
                if cmds.len() == 2 {
                    vfs.cat(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: cat [path]".cyan()).into())
                }
            }

            Commands::NANO => {
                if cmds.len() == 2 {
                    vfs.nano(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: nano [path]".cyan()).into())
                }
            }

            Commands::TOUCH => {
                if cmds.len() == 2 {
                    vfs.touch(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: touch [path]".cyan()).into())
                }
            }

            Commands::MKDIR => {
                if cmds.len() == 2 {
                    vfs.mkdir(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: mkdir [path]".cyan()).into())
                }
            }

            Commands::RMDIR => {
                if cmds.len() == 2 {
                    vfs.rmdir(cmds[1].clone())
                } else {
                    Err(format!("{}", "Usage: rmdir [path]".cyan()).into())
                }
            }

            Commands::CP => {
                if cmds.len() == 3 {
                    vfs.cp(cmds[1].clone(), cmds[2].clone())
                } else {
                    Err(format!("{}", "Usage: cp [from] [to]".cyan()).into())
                }
            }

            Commands::MV => {
                if cmds.len() == 3 {
                    vfs.mv(cmds[1].clone(), cmds[2].clone())
                } else {
                    Err(format!("{}", "Usage: mv [from] [to]".cyan()).into())
                }
            }

            Commands::IMPORT => {
                if cmds.len() == 3 {
                    vfs.import(cmds[1].clone(), cmds[2].clone())
                } else {
                    Err(format!("{}", "Usage: import [from] [to]".cyan()).into())
                }
            }

            Commands::EXPORT => {
                if cmds.len() == 3 {
                    vfs.export(cmds[1].clone(), cmds[2].clone())
                } else {
                    Err(format!("{}", "Usage: export [from] [to]".cyan()).into())
                }
            }

            Commands::INVALID => Ok(println!(
                "{}",
                format!("Invalid command entered `{}`", cmds[0]).red()
            )),
        };

        if let Err(err) = res {
            println!("An error occured:\n\t{err}")
        }
    };

    if let Err(err) = err {
        println!("Error occurred while exiting: {err}\n\tCheck entries before reusing.")
    }
}
