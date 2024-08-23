pub enum Commands {
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
    INVALID,
}

impl From<&str> for Commands {
    fn from(cmd: &str) -> Self {
        match cmd {
            "exit" | "ext" | "e" => Commands::EXIT,
            "touch" | "tch" => Commands::TOUCH,
            "cat" => Commands::CAT,
            "nano" | "nn" => Commands::NANO,
            "cp" => Commands::CP,
            "mv" => Commands::MV,
            "rm" => Commands::RM,
            "ls" => Commands::LS,
            "reset" | "rst" | "r" => Commands::RESET,
            "cd" => Commands::CD,
            "mkdir" => Commands::MKDIR,
            "pwd" => Commands::PWD,
            "rmdir" => Commands::RMDIR,
            "import" | "imp" => Commands::IMPORT,
            "export" | "exp" => Commands::EXPORT,
            "defrag" | "dfrg" => Commands::DEFRAG,
            "help" | "hlp" | "h" => Commands::HELP,
            _ => Commands::INVALID,
        }
    }
}
