
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Level {
     #[default]
    All,
    Info,
    Warning,
    Silent,
}

pub struct SimLogger<'a> {
    level: Level,
    output: Box<dyn std::io::Write + 'a>,
    currnet_line: u32,
    current_chunk: u32,
    created: u64,
}

impl From<u8> for Level {
    fn from(value: u8) -> Self {
        match value {
            0 => Level::All,
            1 => Level::Warning,
            2 => Level::Info,
            _ => Level::Silent,
        }
    }
}

impl <'a>SimLogger<'a> {
    pub fn new(level: Level, output: &'a mut dyn std::io::Write) -> Self {
        Self { level, output: Box::new(output),created:0, current_chunk:0,currnet_line:0 }
    }
    pub fn log(&mut self, level: Level, message: &str) {
        if self.level.clone() as u32 <= level as u32 {
            writeln!(self.output, "{}", message).unwrap();
        }
    }
}
