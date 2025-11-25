use std::{
    fs::{self,File},
    time::{SystemTime,UNIX_EPOCH},
    path::{/*MAIN_SEPARATOR_STR,*/PathBuf},
    io::{Seek},
    fmt::Display,
};
use crate::io;

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
    output: Box<dyn std::io::Write + Sync + Send + 'a>,
}

pub struct LogFile {
    currnet_line: u32,
    current_chunk: u32,
    name: String,
    path: Option<String>,
    file: File,
}

impl From<u32> for Level {
    fn from(value: u32) -> Self {
        match value {
            0 => Level::All,
            1 => Level::Trace,
            2 => Level::Warning,
            3 => Level::Error,
            4 => Level::Info,
            _ => Level::Silent,
        }
    }
}

impl <'a>SimLogger<'a> {
    pub fn new(level: Level, output: impl std::io::Write + Sync + Send +'static) -> Self {
        Self { level, output: Box::new(output) }
    }
    pub fn log(&mut self, level: Level, message: &str) {
        if self.level.clone() as u32 <= level as u32 {
            writeln!(self.output, "{}", message).unwrap();
        }
    }
    pub fn info(&mut self, message: &str) {
        self.log(Level::Info, message)
    }
    pub fn error(&mut self, message: &str) {
        self.log(Level::Error, message)
    }
    pub fn warning(&mut self, message: &str) {
        self.log(Level::Warning, message)
    }
    pub fn trace(&mut self, message: &str) {
        self.log(Level::Trace, message)
    }
    pub fn set_level(&mut self, level: Level) {
        self.level = level
    }
    pub fn set_output(&mut self, output: impl std::io::Write + Sync + Send + 'a) {
        self.output = Box::new(output)
    }
}

impl LogFile {
    pub fn new() -> Self {
        let created = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let name = format!{"simhttp-{}", created};
        let mut path = PathBuf::from(".");
        path.push(name.clone());
        path.set_extension("log");
        let file = File::create(path).expect("can't create log");
    
        LogFile { currnet_line: 0,
            current_chunk: 0,
            path: None,
            name,
            file,
        }
    }
    
    pub fn from(path: impl Into<String>, name: &impl AsRef<str>) -> Self {
        let created = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        //let args = format!("{vec![Box::new(created}"))]; // created 
        let name:String = name.as_ref().to_string();
        let name = simweb::interpolate(&name,&vec![Box::new(&created as &dyn Display)]);
        let path:String=path.into();
        let mut log_path = PathBuf::from(&path);
        log_path.push(name.clone());
        log_path.set_extension("log");
        let file = File::create(&log_path).expect(&format!("can't create log {log_path:?}"));
    
        LogFile { currnet_line: 0,
            current_chunk: 0,
            path: Some(path),
            name,
            file,
        }
    }
    
    pub fn roll (&mut self) {
        self.current_chunk += 1;
        let mut path = match &self.path {
            None => PathBuf::from("."),
            Some (path) => PathBuf::from(path)
        };
        path.push(self.name.clone());
        path.set_extension("log");
        let mut copy_path = path.clone();
        copy_path.set_extension( format!{"log.{:05}", self.current_chunk});

        if fs::copy(path, copy_path).is_ok() && self.file.rewind().is_ok() {
            let _ = self.file.set_len(0);
        }
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