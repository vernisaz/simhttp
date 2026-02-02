extern crate simtpool;
extern crate simjson;
extern crate simweb;
extern crate rslash;
use std::{
    fs::{self,File},
    io::{prelude::*, Error, ErrorKind, BufReader, self},
    net::{TcpListener, TcpStream,ToSocketAddrs,Shutdown},
    thread,
    sync::{atomic::{AtomicBool,Ordering}, Arc,Mutex,LazyLock,OnceLock,mpsc},
    path::{PathBuf},
    collections::HashMap,
    process::{Stdio,Command},
    time::{SystemTime,UNIX_EPOCH,Duration},
    env, convert::TryInto, cmp, error::Error as GenError,
};
use simtpool::ThreadPool;
use simjson::JsonData::{Num,Text,Data,Arr,Bool,self};
use simweb::{http_format_time,parse_http_timestamp};
mod log;
use log::{Level,LogFile};
mod sha1;

#[derive(Debug)]
struct Mapping {
    web_path: String,
    path: String,
    cgi: bool,
    wrapper: Option<String>,
    ext: Option<String>,
    no_headers: bool,
    websocket: bool,
    options: Option<Vec<(String,String)>>, // "Map" doesnt't give benefits over duplication keys 
}

struct CgiOut {
    load: Vec<u8>,
    pos: usize,
}

macro_rules! debug {
    ($($rest:tt)*) => {
        if !NO_TERMINAL.get().unwrap() {
            std::eprintln!($($rest)*)
        }
    }
}

const VERSION : &str = env!("VERSION");

static ERR404: &str = include_str!{"404.html"};

static LOGGER : LazyLock<Mutex<log::SimLogger>> = LazyLock::new(|| Mutex::new(log::SimLogger::new(log::Level::All, io::stdout())));

static MIME: OnceLock<HashMap<String,String>> = OnceLock::new();

static MAPPING: OnceLock<Vec<Mapping>> = OnceLock::new();

static NO_TERMINAL : OnceLock<bool> = OnceLock::new();

static KEEPALIVE_TIMEOUT : OnceLock<u64> = OnceLock::new();

static PING_INTERVAL : OnceLock<u64> = OnceLock::new();

const MAX_LINE_LEN : usize = 64*1024;

const PARSE_NUM_ERR : u16 = 501;

const TYPE_HTML: &str = "text/html";
const TYPE_PLAIN : &str = "text/plain";

fn init_mime(mime: HashMap<String,String>) {
    MIME.set(mime).unwrap();
}

fn init_mapping(mapping: Vec<Mapping>) {
    MAPPING.set(mapping).unwrap()
}

fn init_terminal(no_terminal: bool) -> () {
    NO_TERMINAL.set(no_terminal).unwrap()
}

fn init_keepalive(keepalive_mins: u64) -> () {
    KEEPALIVE_TIMEOUT.set(keepalive_mins).unwrap()
}

fn init_ping_interval(interval_mins: u64) -> () {
    PING_INTERVAL.set(interval_mins).unwrap()
}

fn main() {
    let Ok(env) = fs::read_to_string("env.conf") else {
        eprintln!{"No env.conf file in the current directory"}
        return
    };
    let env = simjson::parse(&env);
    let Data(env) = env else {
        eprintln!{"Corrupted env.conf file in the current directory"}
        return
    };
    if let Some(Data(log)) = env.get("log") {
        if let Some(Data(out)) = log.get("out") {
            if let Some(Text(path)) = out.get("path") {
                let name = 
                if let Some(Text(val)) = out.get("name") {
                   val
                } else {
                   "simhttp-${0}"
                };

                LOGGER.lock().unwrap().set_output(LogFile::from(path,&name))
            } else {
                LOGGER.lock().unwrap().set_output(LogFile::new());
            }
        }
        if let Some(Num(level)) = log.get("level") {
            if let Ok(mut logger) = LOGGER.lock() {
                let level = Level::from(*level as u32);
                logger.info(&format!{"log level set to {:?}", &level});
                logger.set_level(level);
            }
        } else if let Some(Text(val)) = log.get("type") {
            let mut level = 0u32;
            if val.contains("access") {
                level =2
            } else if val.contains("error") {
                level = 3
            } else if val.contains("debug") {
                level = 1
            } else if val.contains("critical") {
                level = 4
            }
            let level = Level::from(level);
            if let Ok(mut logger) = LOGGER.lock() {
                logger.set_level(level);
                logger.info(&format!{"log level set to {:?}", val});
            }
        }
    }
    let no_terminal = if let Some(Bool(val)) = env.get("no terminal") {
         val.to_owned()} else {false};
    init_terminal(no_terminal);
    // TODO if a terminal is there, then can do debug printout on it bypassing log
    
    let Some(Num(tp)) = env.get("threads") else {
        eprintln!{"No number of threads configured"}
        return
    };
    let Some(Text(bind)) = env.get("bind") else {
        eprintln!{"No bound addr is specified"}
        return
    };
    let Some(Num(port)) = env.get("port") else {
        eprintln!{"No port number properly configured"}
        return
    };
    
    let Some(Arr(mapping)) = env.get("mapping") else {
        eprintln!{"No mapping properly configured"}
        return
    };
    let mut mime2 = HashMap::new(); 
    if let Some(Arr(mime)) = env.get("mime") {
        for el in mime {
            if let Data(el) = el &&
                let Some(Text(en)) = el.get("ext") && let Some(Text(typ)) = el.get("type") {
                mime2.insert(en.to_string(),typ.to_string());
            }
        } 
    };
    init_mime(mime2);
    init_keepalive(match env.get("keep_alive_mins") {
        Some(Num(val)) if *val >= 0.0 => *val as u64,
        _ => 10_u64,});
    init_ping_interval(match env.get("ping_interval_mins") {
        Some(Num(val)) => *val as u64,
        _ => 30_u64,});
    
    let tp = ThreadPool::new(*tp as usize);

    let listener = TcpListener::bind(format!{"{bind}:{port}"}).unwrap_or_else(|err| panic!("can't bind {bind} to {port}, probably it's already in use - {err}"));
    let stop = Arc::new(AtomicBool::new(false));
    let stop_one = stop.clone();
    init_mapping(read_mapping(mapping));
    LOGGER.lock().unwrap().info(&format!{"Server started for {bind}:{port}"});
    let stop_listener = listener.try_clone().unwrap();
    if !no_terminal {
       thread::spawn(move || {
            println!{"Presss 'q' to stop"};
            let mut input = String::new();
            loop {
                io::stdin().read_line(&mut input).expect("Failed to read line");
                if input.starts_with("q") {
                    stop_one.store(true, Ordering::SeqCst);
                    break
                }
                input.clear()
            }
            drop(stop_listener)
        });
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else {continue};
        let stop_two = stop.clone();
        //let res_stream = stream.try_clone().unwrap();
        tp.execute(move || {
            loop {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(60*KEEPALIVE_TIMEOUT.get().unwrap())));
                // timeout can be reset at handling long polls
                match handle_connection(&stream)  {
                     Err(err) => { if err.kind() != ErrorKind::BrokenPipe && err.kind() != ErrorKind::ConnectionReset { 
                         LOGGER.lock().unwrap().error(&format!{"Err: {err} - in handling the request"});
                         // can do it only if response isn't commited
                         let _ =report_error(500, "<grabbled> HTTP/1.1", &stream);
                        }
                        break }
                     _ => if stop_two.load(Ordering::SeqCst) { break }
                }
            }
        });
        //drop(res_stream);
        if stop.load(Ordering::SeqCst) { break }
    }
    LOGGER.lock().unwrap().info("Stopping the server...");
    drop(tp)
}

fn handle_connection(mut stream: &TcpStream) -> io::Result<()> {
    let addr =
        match stream.peer_addr() {
            Ok(addr) => addr.to_string(),
            _ => "disconnected".to_string()
        };
    let mut buf_reader = BufReader::new(stream);
    let mut line = String::new();
    //let lines = buf_reader.lines(); // may still work
    let len = buf_reader.read_line(&mut line)?;
    if len < 10 { // http/1.x ...
        if len > 0 {
            LOGGER.lock().unwrap().error(&format!{"bad request 0x{}", simweb::to_hex(line.as_bytes())})}
        return Err(Error::new(ErrorKind::BrokenPipe, "no data"))
    }
    //eprintln!("request {line}");
    let mut close = false;
    line.truncate(len-2); // \r\n
    let request_line = line.clone();
    let mut parts  = request_line.splitn(3, ' '); // split_whitespace
    let method = parts.next().ok_or(io::Error::other("invalid request"))?; // can't be due len check
    let mut path = parts.next().ok_or(io::Error::other("invalid request - no path"))?.to_string();
    let protocol = parts.next().ok_or(io::Error::other("invalid request - no protocol"))?;
    let query = match path.find('?') {
        Some(qp) => {
            let query = &path[qp+1..].to_string();
            path = path[0..qp].to_string();
            query.to_owned()
        }
        None => String::new()
    };

    let mut path_translated = None;
    let mut cgi = false;
    let mut websocket = false;
    let mut script = String::new();
    let mut path_info = None;
    let mut wrapper = None;
    let mut no_headers = false;
    let mapping = MAPPING.get().unwrap();
    let mut preserve_env = false;
    //let mut map_entry = None;
    let mut env_ext = None;
    for e in mapping {
        if path.starts_with(&e.web_path) {
            //map_entry = Some(&e); // investigate why can't holp a pointer to map entry
            if e.websocket && (path == e.web_path || 
                    path[e.web_path.len()..e.web_path.len()+1] == *"/") {
                websocket = true;
                preserve_env = !e.cgi;
                cgi = true;
                let mut ws_file = PathBuf::new();
                ws_file.push(e.path.clone());
                // add ext?
                if cfg!(windows) {
                    ws_file.set_extension("exe");
                }
                if e.web_path.len() < path.len() {
                    path_info = Some(path[e.web_path.len()..].to_string());
                }
                path_translated = Some(ws_file.to_str().unwrap().to_string());
               // eprintln!{"mapping for ws as  {path_translated:?}"}
            } else {
                if path.ends_with('/') {
                    if e.cgi && e.ext.is_some() {
                        path += &("index.".to_owned() + &e.ext.clone().unwrap())
                    } else {
                        path += "index.html"
                    }
                }
                // it can be better to keep web_path as parts
                if e.cgi {
                    let ext = e.ext.clone().unwrap_or_default();
                    
                    // possibly normalize separators here
                    let mut script_parts = path[e.web_path.len()..].split('/');
                    let mut translated = PathBuf::from(e.path.clone());
                    while let Some(part) = script_parts.next() {
                        translated = translated.join(part);
                        if translated.is_dir() {
                            continue
                        } else if translated.is_file() || cfg!(windows) && translated.set_extension("exe") && translated.is_file() { 
                            if ext.is_empty() || !ext.is_empty() && part.len() > ext.len() + 1 && part.ends_with(&ext) && part[part.len()-ext.len()-1..part.len()-ext.len()] == *"." {
                                script = part.to_string();
                                let mut acc = String::new();
                                for e in script_parts.by_ref() {
                                    acc.push('/');
                                    acc.push_str(e)
                                } 
                                if !acc.is_empty() {
                                    path_info = Some(acc)
                                }
                                path_translated = translated.to_str().map(|s| s.to_string());
                                cgi = true;
                                wrapper = e.wrapper.clone();
                                if e.no_headers {
                                    no_headers = e.no_headers
                                }
                                env_ext = e.options.clone();
                                break
                            }
                        } else {
                            return report_error(404,&request_line, stream) // format!("script {part} component doesn't exist")
                        }
                    }
                }
                if script.is_empty() {
                    let path_buf =  PathBuf::from(&e.path);
                    let mut sanitized_parts = PathBuf::new();
                    for part in  simweb::as_web_path(&mut path[e.web_path.len()..].to_string()).split('/') {
                        match part {
                            ".." => {sanitized_parts.pop();}
                            "." => (),
                            some => sanitized_parts.push(some)
                        }
                    }
                    path_translated = Some( path_buf.join(sanitized_parts).to_str().unwrap().to_string());
                }
               // eprintln!{"mapping found as {path_translated:?}"}
            }
            break
        } //else { println!{"path {path} not start with {}", e.web_path} }
    }
    
    let mut content_len = 0_u64;
    let mut since = 0_u64;
    let mut extra = None;
    let mut cgi_env = if cgi {
        let mut env : HashMap<String, String> = if preserve_env {
            env::vars().collect()
        } else {
            env::vars().filter(|(k, _)|
             k == "PATH").collect()
        };
        // CGI spec: https://datatracker.ietf.org/doc/html/rfc3875
        env.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        env.insert("QUERY_STRING".to_string(), query);
        if let Ok(peer_addr) = stream.peer_addr() {
            env.insert("REMOTE_ADDR".to_string(), peer_addr.to_string()); 
            if let Ok(mut remote_host) = peer_addr.to_socket_addrs() {
                env.insert("REMOTE_HOST".to_string(), remote_host.next().unwrap().to_string());
            }
        } 
        env.insert("REQUEST_METHOD".to_string(), method.to_string());
        env.insert("SERVER_PROTOCOL".to_string(), protocol.to_string());
        env.insert("SERVER_SOFTWARE".to_string(), VERSION.to_string());
        if let Some(ref path_info) = path_info {
             env.insert("PATH_INFO".to_string(), path_info.into());
        }
        if let Some(ref path_translated) = path_translated {
            let mut path_translated = PathBuf::from(&path_translated);
            path_translated.pop();
            let mut path_translated = path_translated.as_path().canonicalize()?;
            if !path_translated.is_absolute() {
                 path_translated = env::current_dir()?.join(path_translated)
            }
            let path_translated = if let Some(path_info) = path_info {
                // sanitize path_info
                let mut sanitized_parts = PathBuf::new();
                for part in  rslash::to_unix_separator(path_info).split('/') {
                    match part {
                        ".." => {sanitized_parts.pop();}
                        "." => (),
                        some => sanitized_parts.push(some)
                    }
                }
                path_translated.join(sanitized_parts)
            } else {
                path_translated
            };
            
            env.insert("PATH_TRANSLATED".to_string(), path_translated.to_str().unwrap().to_string());
        }
        if !script.is_empty() {
            env.insert("SCRIPT_NAME".to_string(), script);
        }
        line.clear();
        while 2 < buf_reader.read_line(&mut line)? {
            line.truncate(line.len()-2); // \r\n

            //eprintln!{"heare: {line}"}
            if let Some((key,val)) = line.split_once(": ") {
                let key = key.to_lowercase();
                let key = key.as_str();
                match key {
                    "user-agent" => {env.insert("REMOTE_IDENT".to_string(), val.to_string());}
                    "host" => {
                        if let Some((host,port)) = val.split_once(':') {
                           env.insert("SERVER_NAME".to_string(), host.to_string());
                           env.insert("SERVER_PORT".to_string(), port.to_string());
                        }
                    }
                    "content-length" => { // read load 
                        if let Ok(len) = val.parse::<u64>() {
                            content_len = len
                        }
                        env.insert("CONTENT_LENGTH".to_string(), val.trim().to_string());
                    }
                    "content-type" => {
                        env.insert("CONTENT_TYPE".to_string(), val.trim().to_string());
                    }
                    "authorization" => {
                        env.insert("AUTH_TYPE".to_string(), val.to_string());
                    }
                    _ => {env.insert("HTTP_".to_owned() + &key.to_uppercase().replace("-", "_").to_string(), val.to_string());},
                }
            } else {
                 LOGGER.lock().unwrap().error(&format!{"unrecognized header {line}"})
            }
            line.clear()
        }
        if !env.contains_key("CONTENT_TYPE") {
            env.insert("CONTENT_TYPE".to_string(), TYPE_PLAIN.to_string());
        }
        if content_len > 0 {
            let mut buffer = vec![0u8; content_len as usize];
             buf_reader.read_exact(&mut buffer)?;
            //println!{"input:-> {}", String::from_utf8_lossy( &buffer)}
            extra = Some(buffer)
        }
        if !websocket && env. get("HTTP_UPGRADE") == Some(&"websocket".to_string()) {
            return report_error(404, &request_line, stream)
        }
        Some(env)
    } else { 
        line.clear();
        while 2 < buf_reader.read_line(&mut line)? {
            line.truncate(line.len()-2); // \r\n
            //eprintln!{"header: {line}"}
            if let Some((key,val)) = line.split_once(": ") {
                 let key = key.to_lowercase();
                match key.as_str() {
                    "content-length" => {  
                        content_len = val.parse::<u64>().unwrap_or(0); 
                    }
                    "if-modified-since" => {
                        since = parse_http_timestamp(val).unwrap_or(0)
                    }
                    "connection" => close = val != "keep-alive",
                    "referer" | "user-agent" => LOGGER.lock().unwrap().trace(&format!("{key}: {val}")),
                    &_ => () // all headers should be collected somewhere
                }
            }
            line.clear();
        }
        if content_len > 0 {
            io::copy(&mut buf_reader.by_ref().take(content_len), &mut std::io::sink())?;
            //buf_reader.seek_relative(content_len)?
        }
        None };
        
    if method == "GET" || method == "POST" {
        // eprintln!{"servicing {method} to {path_translated:?} {cgi} {websocket}"}
        match path_translated {
            Some(ref path_translated) if PathBuf::from(&path_translated).is_file() => {
                let path_translated = PathBuf::from(&path_translated);
                if cgi {
                    let mut path_translated = path_translated.as_path().canonicalize().unwrap();
                    if !path_translated.is_absolute() {
                         path_translated = env::current_dir()?.join(path_translated)
                    }
                    if websocket {
                        // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
                        // generate a respose first
                        // it can be generate by WS CGI, but
                        let cgi_env = cgi_env.unwrap();
                        let key = &cgi_env.get("HTTP_SEC_WEBSOCKET_KEY").unwrap();
                        let mut hasher = sha1::Sha1::new();
                        let res = hasher.hash(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
                        //eprintln!{"ws command {path_translated:?}"}
                        let mut load = Command::new(&path_translated)
                         .stdout(Stdio::piped())
                         .stdin(Stdio::piped())
                         .stderr(Stdio::piped())
                         .current_dir(path_translated.parent().unwrap())
                         .env_clear() // can be a flag telling to purge system env or not
                        .envs(cgi_env).spawn()?;
                        
                        let res = simweb::base64_encode_with_padding(&res);
                        let mes = response_message(101);
                        let response =
                            format!("{protocol} 101 {mes}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {res}\r\n\r\n");
                        stream.write_all(response.as_bytes())?;
                        // log
                        LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" 101 0",
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()});
                        let _ = stream.set_read_timeout(None);
                        let mut reader_stream = stream;//.try_clone().unwrap();
                        let mut stdin = load.stdin.take().unwrap(); // TODO can be no stdin endpoint just sending out some info, or for example file content
                        let stderr  = load.stderr.take().unwrap();
                        let mut stdout = load.stdout.take() .unwrap();
                        let (send, recv) = mpsc::channel();
                        let pong_resp = Arc::new(Mutex::new(0_u64));
                        let shared_data_writer = Arc::clone(&pong_resp);
                        thread::scope(|s| {
                            s.spawn( || {
                                let mut buffer = [0_u8;MAX_LINE_LEN];
                                let mut reminder = 0_usize;
                                'serv_ep: loop {
                                    let mut complete = false;
                                    let mut kind = 0u8;
                                    let mut fin_data = vec![];
                                    // TODO incorporate all logic in this while to decode_block and hide the mask exposing
                                    while !complete {
                                        // reminder can be enouth to start decoding the block
                                        let len;
                                        if reminder >= 8 {
                                            len = reminder;
                                            reminder = 0
                                        } else {
                                            len = match reader_stream.read(&mut buffer[reminder..]) {
                                                Ok(len) => if len == 0 { break 'serv_ep} else { len },
                                                Err(_) => break 'serv_ep,
                                            };
                                        }
                                        debug!("decode bl of {len}/{reminder}");
                                        if reminder  + len <= 2 {
                                            // read more data because even close(8) has to include mask
                                            reminder += len;
                                            continue
                                        }
                                        
                                        let Ok((mut data,bl_kind,last,mut extra,mask,mut mask_pos,remain)) = decode_block(&mut buffer[0..len + reminder])
                                            .inspect_err(|e| LOGGER.lock().unwrap().error(&format!("decode bl {len} + {reminder} - err:{e}"))) else {
                                            debug!("invalid block of {len} + {reminder}={}, WS's closing", len + reminder);
                                            break 'serv_ep
                                        };
                                        if data.is_empty() && extra == 0 && u32::from_be_bytes(mask) == 0 { // need more data to decode the buffer
                                            debug!("need more data {reminder} - len: {len}");
                                            reminder += len;
                                            continue
                                        }
                                        if remain { // there are data in buffer
                                            debug!("there are {extra} byte(s) of data for further processing in the buffer");
                                            reminder = extra;
                                        } else {
                                            debug!("required to read {extra} for bl {bl_kind} to complete initial {}", data.len());
                                            reminder = 0;
                                            while extra > 0 {
                                                let len = match reader_stream.read(&mut buffer) {
                                                    Ok(len) => if len == 0 { break 'serv_ep} else { len },
                                                    Err(_) => break 'serv_ep,
                                                };
                                                debug!("incomplete bl {bl_kind} requires reading {extra} more, currently {len} of {} last={last}", data.len());
                                                
                                                for i in 0..len {
                                                    extra -= 1;
                                                    //debug!("unmask {:x} ^ {:x}", buffer[i] , mask[mask_pos]);
                                                    data.push(buffer[i] ^ mask[mask_pos]);
                                                    mask_pos = (mask_pos + 1) % 4;
                                                    if extra == 0 /*&& i < len - 1*/ {
                                                        reminder = len-i-1;
                                                        debug!("there are additional bytes {reminder} in buffer");
                                                        buffer.copy_within(i+1..len, 0);
                                                        break
                                                    }
                                                }
                                            }
                                        }
                                        if kind == 0 {
                                            kind = bl_kind;
                                        }
                                        complete = last;
                                        fin_data.append(&mut data);
                                    }
                                    debug!("complete {complete} -> {} of kind {kind} remained {reminder}", fin_data.len());
                                    match kind {
                                        0 => { // not supporting continuation yet, ignore for now
                                            continue
                                        }
                                        1 => (),
                                        8 => { // close websocket
                                            break
                                        }
                                        0x9 => { // ping
                                            // a client usually doesn't send, error ?
                                            continue // ignore for now
                                        }
                                        0xA => { // pong
                                            // check if we sent matching ping and clear it
                                            //let pong_len = fin_data.len();
                                            let pong_data = if fin_data.len() == 8 { u64::from_be_bytes(fin_data.try_into().unwrap()) } else { 0_u64 };
                                            let mut data = shared_data_writer.lock().unwrap(); // Acquire the lock
                                            *data = pong_data;
                                            //LOGGER.lock().unwrap().info(&format!("received pong len {pong_len} as {pong_data}"));
                                            continue 
                                        }
                                        2 => { // currently support only UTF8 strings, no continuation or binary data
                                            LOGGER.lock().unwrap().error(&format!("binary block is not supported yet {fin_data:?}"));
                                            continue
                                        }
                                        _ => {
                                            LOGGER.lock().unwrap().error(&format!("block {kind} is wrong"));
                                            break // because more likely something wrong with the client 
                                        }
                                        
                                    }
                                    // TODO think how pass a block size to endpoint as: 1. in from 4 chars len, or 2. end mark like 0x00
                                    if stdin.write_all(fin_data.as_slice()).is_err() {break};
                                    stdin.flush().unwrap();
                                    //let string = String::from_utf8_lossy(&data);
                                    //eprintln!("entered {string}");
                                }
                                
                                if let Ok(()) = stdin.write_all(&[255_u8,255,255,4]) { stdin.flush().unwrap() } // TODO consider also using 6 - Acknowledge
                                LOGGER.lock().unwrap().info(&format!("websocket session has terminated, endpoint {path_translated:?} will be killed"));
                                // forsibly kill the endpoint at a websocket disconnection
                                #[cfg(extra_stable)] // set in case of instability
                                load.kill().expect("command couldn't be killed"); 
                                //eprintln!("need to terminate endpoint! Killed?");
                            });
                            // stderr
                            s.spawn(|| {
                                let err = BufReader::new(stderr);
                                err.lines().for_each(|line|
                                    LOGGER.lock().unwrap().error(&format!("err: {}", line.unwrap()))
                                );
                            }) ;
                            let mut heartbeat_stream = stream.try_clone().unwrap();
                            let shared_data_reader = Arc::clone(&pong_resp);
                            if *PING_INTERVAL.get().unwrap() > 0 {
                                let _heartbeat_handle = s.spawn(move || {
                                    let mut count = 0_u64;
                                    // TODO write ping and check for receiving pong can be done in one heartbeat thread for all websockets
                                    loop {
                                        count += 1;
                                        match heartbeat_stream.write_all(encode_ping(&count.to_be_bytes()).unwrap().as_slice()) {
                                            Err(_) => break,
                                            _ => heartbeat_stream.flush().unwrap(),
                                        }
                                        if recv.recv_timeout(Duration::from_secs(60*PING_INTERVAL.get().unwrap())).is_ok() {
                                            break; // Handle the interruption
                                        }
                                        // check if pong with count received
                                        let data = shared_data_reader.lock().unwrap();
                                        if count != *data {
                                            debug!("no matching pong data, closing stream");
                                            let _ = heartbeat_stream.shutdown(Shutdown::Both); // shutdown TCP stream
                                            break
                                        }
                                        drop(data);
                                    }
                                });
                            } 
                            let mut writer_stream = stream;
                            let mut buffer = [0_u8;MAX_LINE_LEN]; 
                            while let Ok(len) = stdout.read(&mut buffer) {
                                if len == 0 || writer_stream.write_all(encode_block(&buffer[0..len]).as_slice()).is_err() { break }
                            }
                            match writer_stream.write_all(&[0x88,0]) {
                                _ => ()
                            }
                            let _ = send.send(());
                        });
                        // TODO need a thread for stdout read loop
                        load.wait().unwrap();
                        return Err(Error::new(ErrorKind::BrokenPipe, "Websocket closed")) // force to close the connection and don't try to reuse
                    }
                    if let Some(ref mut cgi_env) = cgi_env && let Some(options) = env_ext {
                        for (name,value) in options {
                            cgi_env.insert(name, match value.as_str() {
                                "$SCRIPT_FILE" => path_translated.display().to_string(),
                                "$IP" => format!("{}", stream.local_addr().unwrap().ip()),
                                _ => value,
                            });
                        }
                    }
                    let mut load =
                    if let Some(wrapper) = wrapper {
                        Command::new(wrapper)
                         .stdout(Stdio::piped())
                         .stdin(Stdio::piped())
                         .stderr(Stdio::piped())
                         //.arg(&path_translated) TODO provide a mechanism how script reaches the wrapper
                         .current_dir(path_translated.parent().unwrap())
                         .env_clear()
                        .envs(cgi_env.unwrap()).spawn()?
                    } else {
                        Command::new(&path_translated)
                         .stdout(Stdio::piped())
                         .stdin(Stdio::piped())
                         .stderr(Stdio::piped())
                         .current_dir(path_translated.parent().unwrap())
                         .env_clear()
                        .envs(cgi_env.unwrap()).spawn()?
                    };
                    
                    if let Some(extra) = extra && let Some(mut stdin) = load.stdin.take() {
                        thread::spawn(move || // TODO consider using a separate thread pool
                            if let Err(err) = stdin.write_all(&extra) { LOGGER.lock().unwrap().error(&format!{"can't write to SGI script: {err}"}) }
                        );
                    }
                    let _ = stream.set_read_timeout(None);
                    let output = load.wait_with_output()?;
                    let err = BufReader::new(&*output.stderr);
                    err.lines().for_each(|line| {
                        LOGGER.lock().unwrap().trace(& line.unwrap()); // maybe to do not lock for every line and do everything in batch?
                    });
                   // println!{"load {}", String::from_utf8_lossy( &output.stdout)}
                    let mut output = CgiOut{load:output.stdout, pos:0};
                    let mut code_num = 200;
                    let status = if !no_headers {output.next()} else {None};
                    if let Some(status) = status {
                        let mut headers = String::new();
                        // first line
                        let mut status =
                            if let Some((key,val)) = status.split_once(": ") {
                                let key = key.to_lowercase();
                                if key != "content-length" && key != "status" {
                                    headers.push_str(&format!{"{status}\r\n"});
                                }
                                if key == "location" {
                                    code_num = 302;
                                    format!{"{protocol} 302 Found\r\n"}
                                } else if key == "status" {
                                    if let Some((code, _)) = val.split_once(' ') {
                                        code_num = code.parse::<u16>().unwrap_or(PARSE_NUM_ERR);
                                        format!{"{protocol} {val}\r\n"}
                                    } else {
                                        code_num = val.parse::<u16>().unwrap_or(PARSE_NUM_ERR);
                                        let msg = response_message(code_num);
                                        format!{"{protocol} {val} {msg}\r\n"}
                                    }
                                } else {
                                    format!{"{protocol} 200 OK\r\n"}
                                }
                            } else {
                                let (code, msg) = 
                                match status.split_once(' ') {
                                    Some((code,msg)) => {
                                        code_num = code.parse::<u16>().unwrap_or(PARSE_NUM_ERR);
                                        (code.to_string(),msg.to_string())
                                    },
                                    None => {
                                        code_num = status.parse::<u16>().unwrap_or(PARSE_NUM_ERR);
                                        (status,response_message(code_num).to_string())
                                    }
                                };
                                format!{"{protocol} {code} {msg}\r\n"}
                            };
                        let mut was_content_type = false;
                        while let Some(mut header)  = output.next() {
                            header = header.trim().to_string(); // consider simple trunc(2)
                            if let Some((key,val)) = header.split_once(": ") {
                                let key = key.to_lowercase();
                                if key == "location" {
                                    code_num = 302;
                                    status = format!{"{protocol} 302 Found\r\n"}
                                } else if key == "status" && let Some((code, _)) = val.split_once(' ') {
                                    code_num = code.parse::<u16>().unwrap_or(PARSE_NUM_ERR); // should reject the request if status code unparsable
                                    status = format!{"{protocol} {val}\r\n"}
                                } else if key == "content-type" {
                                    was_content_type = true;
                                }
                                if key != "content-length" && key != "status" {
                                    headers.push_str(&format!{"{header}\r\n"})
                                } 
                            }
                        }
                        if !was_content_type {
                            headers.push_str("Content-Type: text/html\r\n")
                        }
                        stream.write_all(status.as_bytes())?;
                        stream.write_all(headers.as_bytes())?;
                        let len = output.rest_len() ; // why not content-length ?
                        //eprintln!{"{status}{headers}Content-Length: {len}"}
                        stream.write_all(format!{"Content-Length: {len}\r\n\r\n"}.as_bytes())?;
                        if len > 0 {
                            stream.write_all(&output.rest())?;
                            //eprintln!{"{:?}", String::from_utf8_lossy(&output.rest())}
                        }
                    } else {  // no headers
                        let len = output.rest_len() ;
                        let text_html = TYPE_PLAIN.to_string();
                        let c_type = 
                        if let Some(ext) = path_translated. extension() {
                            MIME.get().unwrap().get(ext.to_str().unwrap()).unwrap_or(&text_html)
                        } else {&text_html};
                        stream.write_all(format!{"{protocol} 200 OK\r\nContent-Type: {c_type}\r\nContent-Length: {len}\r\n\r\n"}.as_bytes())?;
                        if len > 0 {
                            stream.write_all(&output.all()).unwrap()
                        }
                    }
                    LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" {code_num} {}",
                       SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(), output.rest_len()})
                } else {
                    let modified = fs::metadata(&path_translated)?.modified()?;
                    if since > 0 && modified.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs() < since {
                        let response =
                            format!("{protocol} 304 {}\r\n\r\n", response_message(304));
                        stream.write_all(response.as_bytes())?;
                        // log
                        LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" 304 0", 
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()});
                        return Ok(())    
                    }
                    let mut f = File::open(&path_translated)?;
                    let mut buffer = Vec::new();
                    let c_type =
                    if let Some(ext) = path_translated. extension() {
                        MIME.get().unwrap().get(ext.to_str().unwrap()).map_or("octet-stream", |e| e)
                    } else {"octet-stream"};
                    // read the whole file
                    f.read_to_end(&mut buffer)?;
                    
                    let time = http_format_time(modified);
                    let length = buffer.len();
                    let response =
                        format!("{protocol} 200 OK\r\nContent-Length: {length}\r\nContent-Type: {c_type}\r\nLast-modified: {time}\r\n\r\n");
                
                    stream.write_all(response.as_bytes())?;
                    stream.write_all(&buffer)?;
                    // log
                    LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" 200 {length}", 
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()})
                }
            }
            _ => {
                report_error(404,&request_line, stream)?
            }
        }
    } else { // PUT DELETE HEAD TRACE OPTIONS PATCH CONNECT
        // unsupported method
        report_error(405, &request_line, stream)?
    }
    if close {
        Err(Error::other("requested close"))
    } else {
        Ok(())
    }
}

fn read_mapping(mapping: &Vec<JsonData>) -> Vec<Mapping> {
    let mut res = Vec::new();
    for e in mapping {
        let Data(e) = e else { continue };
        let Some(Text(path)) = e.get("path") else { continue; };
        
        let Some(Text(trans)) = e.get("translated") else { continue };
        let cgi = match e.get("CGI") {
            Some(Bool(cgi)) => cgi,
            _ => &false
        };
        let websocket = match e.get("WS-CGI") {
            Some(Bool(websocket)) => {
                    if *cgi && *websocket {
                        LOGGER.lock().unwrap().warning(&format!{"Note: WS_CGI overrules CGI for {path}, however all OS env variables will be cleared as for CGI."});
                    }
                    websocket},
            _ => &false
        };
        let ext = e.get("ext").map(|ext| if let Text(ext) = ext { Some(ext.clone())} else {None}).unwrap_or(None);
        let wrapper =  e.get("engine").map(|wrapper| if let Text(wrapper) = wrapper { Some(wrapper.clone())} else {None}).unwrap_or(None);
        let no_headers = e.get("headerless").map(|val| if let Bool(val) = val { val } else {&false}).unwrap_or(&false);
        let mut options_res = vec![];
        if let Some(Arr(options)) = e.get("options") {
            for option in options {
                if let Data(option) = option 
                    && let Some(Text(name)) = option.get("name") 
                    && let Some(Text(value)) = option.get("value") {
                    options_res.push((name.to_string(),value.to_string()))
                }
            }
        }
        // TODO check for duplication web_path
        res.push(Mapping{ web_path:if *websocket || path.ends_with("/") {path.to_string()} else {path.to_string()  + "/"},
            path: trans.into(), cgi: *cgi, websocket: *websocket, ext,  wrapper, no_headers: *no_headers,
            options: if options_res.is_empty() { None } else { Some(options_res)}, })
    }
    res.sort_by(|a, b| b.web_path.len().cmp(&a.web_path.len()));
    res
}

fn report_error(code: u16, request_line: &str, mut stream: &TcpStream) -> io::Result<()> {
    let contents = if code == 404 {
        ERR404.as_bytes()
    } else {
        let path = PathBuf::from(&format!{r"{code}.html"});
        if path.is_file() {
            &fs::read(&path)?
        } else {
            ERR404.as_bytes()
        }
    };
    let length = contents.len();
    let protocol = "HTTP/1.1";
    let msg = response_message(code);
    let response =
        format!("{protocol} {code} {msg}\r\nContent-Length: {length}\r\nContent-Type: {TYPE_HTML}\r\n\r\n");

    stream.write_all(response.as_bytes())?;
    stream.write_all(contents)?;
    // log
    let addr =
        match stream.peer_addr() {
            Ok(addr) => addr.to_string(),
            _ => "disconnected".to_string()
        };
    LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" {code} {length}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()});
    Ok(())
}

fn encode_ping(input: &[u8]) -> Result<Vec<u8>, Box<dyn GenError>> { 
    let len = input.len();
    if len > 126 {
        return Err("payload len for ping > 126".into())
    }
    let mut res = Vec::with_capacity(len+2);
    res.push(0x89_u8); // no cont (last), ping
    match len as u8 {
        0..126 => {
            res.push(len as u8); // not masked
        }
        _ => unreachable!("wrong {}", len) // 0 is filtered out to do not call the method
    }
    if len > 0 {
        // no 4 bytes mask for server to client
        res.extend_from_slice(input);
    }
    Ok(res)
}

fn encode_block(input: &[u8]) -> Vec<u8> { // TODO add param - start, mid and the last block
    let len = input.len();
    //eprintln!("encoding bl {len}");
    let mut res = Vec::with_capacity(len+5);
    res.push(0x81_u8); // no cont (last), text
    match len as u64 {
        1..126 => {
            res.push(len as u8); // not masked
        }
        126..0x10000_u64 => { // u16::MAX
            res.push(126_u8); // not masked
            res.extend_from_slice(&(len as u16).to_be_bytes())
        }
        0x10000_u64..=u64::MAX => {
            res.push(127_u8); // not masked
            res.extend_from_slice(&(len as u64).to_be_bytes())
        }
        _ => unreachable!("wrong len: {len}") // 0 is filtered out to do not call the method
    }
    // no 4 bytes mask for server to client
    res.extend_from_slice(input);
    res
}

type DecodedBlockData = (Vec<u8>, u8, bool,usize,[u8;4],usize,bool);

fn decode_block(input: &mut [u8]) -> Result<DecodedBlockData,String> {  
    let buf_len = input.len();
    let mut res = Vec::new ();
    if buf_len < 2 { // actually wait for more data
        // not enough data to decode the block
        return Ok((res, 0, false, 0,[0u8;4],0, false))
    }
    
    let last = input[0] & 0x80 == 0x80;
    let op = input[0] & 0x0f;
    let masked = input[1] & 0x80 == 0x80;
    if !masked {
        return Err(format!("client data have to be masked - op: {op}"))
    }
    // reconsider the below fragment to return for more data if len can't be calculated
    let (len, mut shift) = 
    match input[1] & 0x7f {
        len @ 0..=125 => (len as usize, 2_usize),
        126 => if buf_len >= 4 {(u16::from_be_bytes(input[2..4].try_into().unwrap()) as usize, 4_usize)} else {(0usize,buf_len)},
        127 => if buf_len >= 10 {(u64::from_be_bytes(input[2..10].try_into().unwrap()) as usize, 10_usize)}
          else {(0usize,buf_len)},
        128_u8..=u8::MAX => unreachable!(), // because highest bit is cleaned
    };
    if buf_len < shift + 4 { // request to get more block data
        return Ok((res, op, last, 0,[0u8;4],0, false))
    }
    let mut curr_mask = 0;
    let mask;
    if masked { // redundant if because else branch is never triggered
        mask = [input[shift],input[shift+1],input[shift+2],input[shift+3]];
        shift += 4
    } else {
        mask = [0u8;4]
    }
    res.reserve(cmp::min(len, buf_len)); 
    let extra;
    let mut remain = false;
    let data_len = buf_len - shift;
    
    if data_len == len { // merge with last branch
        for _i in 0..len {
            res.push(input[shift] ^ mask[curr_mask]);
            shift += 1;
            curr_mask = (curr_mask + 1) % 4
        }
        extra = 0
    } else if data_len < len {
        for _i in 0..data_len {
            res.push(input[shift] ^ mask[curr_mask]);
            shift += 1;
            curr_mask = (curr_mask + 1) % 4
        }
        extra = len - data_len
    } else if data_len > len {
        for _i in 0..len {
            res.push(input[shift] ^ mask[curr_mask]);
            shift += 1;
            curr_mask = (curr_mask + 1) % 4
        }
        remain = true;
        extra = data_len - len
    } else {
        extra = 0
    }
    if remain && extra > 0 {
        input.copy_within(shift..buf_len, 0);
    }
    Ok((res, op, last, extra, mask, curr_mask, remain))
}

fn response_message(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "Unknown",
    }
}

impl CgiOut {
    fn next(&mut self) -> Option<String> {
        let start = self.pos;
        let mut met = false;
        while self.pos < self.load.len() {
            if met && self.load[self.pos] == b'\n' {
                if self.pos - start <= 2 {
                    return None
                } else {
                    return Some(String::from_utf8(self.load[start..self.pos-1].to_vec()).unwrap()) // lossy ?
                }
            } else { met = false }
            if self.load[self.pos] == b'\r' { met = true; }
            self.pos += 1
        }
        self.pos = start;
        None
    }
    
    fn rest_len(&mut self) -> usize {
        if self.load.is_empty() {
            0
        } else {
            self.load.len() - self.pos - 1
        }
    }
    
    fn rest(&mut self) -> Vec<u8> {
        self.load[self.pos+1..].to_vec()
    }
    
    fn all(&mut self) -> Vec<u8> {
        self.load[..].to_vec()
    }
}

/*fn read_n<R>(reader: R, bytes_to_read: u64) -> Vec<u8>
where
    R: Read,
{
    let mut buf = vec![];
    let mut chunk = reader.take(bytes_to_read);
    // Do appropriate error handling for your situation
    // Maybe it's OK if you didn't read enough bytes?
    let n = chunk.read_to_end(&mut buf).expect("Didn't read enough");
    assert_eq!(bytes_to_read as usize, n);
    buf
}*/