use std::{
    fs::{File},
    time::{SystemTime,UNIX_EPOCH},
    path::{/*MAIN_SEPARATOR_STR,*/PathBuf},
    sync::{Mutex},
};
use io;

static MAX_LINES: u32 = 10_1000;

#[derive(Debug, Clone, PartialEq, Default)]
pub enum Level {
     #[default]
    All,
    Trace,
    Warning,
    Error,
    Info,
    Silent,
}

pub struct SimLogger<'a> {
    level: Level,
    output: Mutex<Box<dyn std::io::Write + Sync + Send + 'a>>,
}

pub struct LogFile {
    currnet_line: u32,
    current_chunk: u32,
    created: u64,
    file: File,
}

impl <'a>SimLogger<'a> {
    pub fn new(level: Level, output: impl std::io::Write + Sync + Send +'static) -> Self {
        Self { level, output: Mutex::new(Box::new(output)) }
    }
    pub fn log(&mut self, level: Level, message: &str) {
        if self.level.clone() as u32 <= level as u32 {
            writeln!(self.output.lock().unwrap(), "{}", message).unwrap();
        }
    }
    pub fn info(&mut self, message: &str) {
        self.log(Level::Info, message)
    }
    pub fn warning(&mut self, message: &str) {
        self.log(Level::Warning, message)
    }
}

impl LogFile {
    pub fn new() -> Self {
        let created = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let name = format!{"simhttp-{}", created};
        let mut path = PathBuf::from(".");
        path.set_file_name(&name);
        path.set_extension("log");
        let file = File::create(path).expect("can't create log");
    
        LogFile { currnet_line: 0,
        current_chunk: 0,
        created: created,
        file: file,
        }
    }
    
    pub fn roll (&mut self) {
        self.current_chunk += 1;
        let name = format!{"simhttp-{}.{:05}", self.created, self.current_chunk};
        let mut path = PathBuf::from(".");
        path.set_file_name(&name);
        path.set_extension("log");
        self.file = File::create(path).expect("can't create log");
    }
}
impl std::io::Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write_all(buf)?;
        if buf[buf.len()-1] == b'\n' { // add count of all \n in the string
            self.currnet_line += 1;
            if self.currnet_line > MAX_LINES {
                self.roll();
                self.currnet_line = 0;
            }
        }
        
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // In this simple example, flush does nothing.
        Ok(())
    }
}