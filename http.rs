extern crate simtpool;
extern crate simjson;
extern crate rslash;
extern crate simweb;
use std::{
    fs::{self,File},
    io::{prelude::*, Error, ErrorKind, BufReader, self},
    net::{TcpListener, TcpStream,ToSocketAddrs},
    thread,
    sync::{atomic::{AtomicBool,Ordering}, Arc,Mutex,LazyLock,OnceLock},
    path::{MAIN_SEPARATOR_STR,PathBuf},
    collections::HashMap,
    process::{Stdio,Command},
    time::{SystemTime,UNIX_EPOCH,Duration},
    env,
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
    websocket: bool,
}

struct CgiOut {
    load: Vec<u8>,
    pos: usize,
}

const VERSION : &str = "SimHTTP/1.12b48";

static ERR404: &str = include_str!{"404.html"};

static LOGGER : LazyLock<Mutex<log::SimLogger>> = LazyLock::new(|| Mutex::new(log::SimLogger::new(log::Level::All, io::stdout())));

static MIME: OnceLock<HashMap<String,String>> = OnceLock::new();

static MAPPING: OnceLock<Vec<Mapping>> = OnceLock::new();

const MAX_LINE_LEN : usize = 64*1024;

const PARSE_NUM_ERR : u16 = 501;

fn init_mime(mime: HashMap<String,String>) {
    MIME.set(mime).unwrap();
}

fn init_mapping(mapping: Vec<Mapping>) {
    MAPPING.set(mapping).unwrap()
}

fn main() {
    let Ok(env) = fs::read_to_string("env.conf") else {
        eprintln!{"No env file in the current directory"}
        return
    };
    let env = simjson::parse(&env);
    let Data(env) = env else {
        eprintln!{"Corrupted env file in the current directory"}
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
        }
    }
    let no_terminal = if let Some(Bool(val)) = env.get("no terminal") {
         val.to_owned()} else {false};
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
        eprintln!{"No mapping properly  configured"}
        return
    };
    let mut mime2 = HashMap::new(); 
    if let Some(Arr(mime)) = env.get("mime") {
        for el in mime {
            if let Data(el) = el {
                if let Some(Text(en)) = el.get("ext") {
                    if let Some(Text(typ)) = el.get("type") {
                        mime2.insert(en.to_string(),typ.to_string());
                    }
                }
            }
        } 
    };
    init_mime(mime2);
    
    let tp = ThreadPool::new(*tp as usize);

    let listener = TcpListener::bind(format!{"{bind}:{port}"}).expect("can't bind {bind} to {port}, probably is already in use");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_one = stop.clone();
    init_mapping(read_mapping(mapping));
    LOGGER.lock().unwrap().info(&format!{"Server started fot {bind}:{port}"});
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
        let Ok(mut stream) = stream else {continue};
        let stop_two = stop.clone();
        tp.execute(move || {
            loop {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(60*10)));
                // timeout can be reset at handling long polls
                match handle_connection(&stream)  {
                     Err(err) => if err.kind() != ErrorKind::BrokenPipe && err.kind() != ErrorKind::ConnectionReset { 
                         LOGGER.lock().unwrap().error(&format!{"Err: {err} - in handling a request"});
                         // can do it only if response isn't commited
                         let contents = ERR404; // 500
                         let contents = contents.as_bytes();
                         let length = contents.len();
                         let c_type = "text/html";
                         
                        if stream.write_all(format!("HTTP/1.1 500 {}\r\nContent-Length: {length}\r\nContent-Type: {c_type}\r\n\r\n", response_message(500)).as_bytes()).is_ok() {
                            if stream.write_all(&contents).is_err() { break }
                            let addr =
                                match stream.peer_addr() {
                                    Ok(addr) => addr.to_string(),
                                    _ => "disconnected".to_string()
                                };
                            LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"... ... HTTP/1.1\" 500 {length}",
                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()});
                        } else {break}
                     } else { break}
                     _ => if stop_two.load(Ordering::SeqCst) { break }
                }
            }
        });
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
    let mut close = false;
    line.truncate(len-2); // \r\n
    let request_line = line.clone();
    let mut parts  = request_line.splitn(3, ' '); // split_whitespace
    let method = parts.next().ok_or(io::Error::new(ErrorKind::Other, "Invalid request"))?; // can't be due len check
    let mut path = parts.next().ok_or(io::Error::new(ErrorKind::Other, "Invalid request - no path"))?.to_string();
    let protocol = parts.next().ok_or(io::Error::new(ErrorKind::Other, "Invalid request - no protocol"))?;
    let query = match path.find('?') {
        Some(qp) => {
            let query = &path[qp+1..].to_string();
            path = path[0..qp].to_string();
            query.to_owned()
        }
        None => "".to_string()
    };

    let mut path_translated = None;
    let mut cgi = false;
    let mut websocket = false;
    let mut name = "".to_string();
    let mut path_info = None;
    let mapping = MAPPING.get().unwrap();
    let mut preserve_env = false;
    for e in mapping {
        if path.starts_with(&e.web_path) {
            cgi = e.cgi;
            if cgi  {
                let mut cgi_file = PathBuf::new();
                cgi_file.push(e.path.clone());
                name = path[e.web_path.len()..].to_string();
                path_info = if let Some(pos) = name.find('/') {
                    let temp = name[pos..].to_string();
                    name = name[..pos].to_string();
                    Some(temp)
                } else {
                    None
                };
                if cfg!(windows) {
                    name = name + ".exe";}
                path_translated = Some(rslash::adjust_separator(e.path.clone() + MAIN_SEPARATOR_STR + &name))
            } else if e.websocket && (path == e.web_path || 
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
                if path.chars().rev().nth(0) == Some('/') {
                    path += "index.html"
                }
                let path_buf =  PathBuf::from(&e.path);
                let mut sanitized_parts = PathBuf::new();
                for part in  rslash::to_unix_separator(path[e.web_path.len()..].to_string()).split('/') {
                    match part {
                        ".." => {sanitized_parts.pop();}
                        "." => (),
                        some => sanitized_parts.push(some)
                    }
                }
                path_translated = Some( path_buf.join(sanitized_parts).to_str().unwrap().to_string());
               // eprintln!{"mapping found as {path_translated:?}"}
            }
            break
        } //else { println!{"path {path} not start with {}", e.web_path} }
    }
    
    let mut content_len = 0_u64;
    let mut since = 0_u64;
    let mut extra = None;
    let cgi_env = if cgi {
        let mut env : HashMap<String, String> = if preserve_env {
            env::vars().collect()
        } else {
            env::vars().filter(|&(ref k, _)|
             k != "PATH").collect()
        };
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
        if !name.is_empty() {
            env.insert("SCRIPT_NAME".to_string(), name);
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
            env.insert("CONTENT_TYPE".to_string(), "text/plain".to_string());
        }
        if content_len > 0 {
            let mut buffer = vec![0u8; content_len as usize];
             buf_reader.read_exact(&mut buffer)?;
            //println!{"input:-> {}", String::from_utf8_lossy( &buffer)}
            extra = Some(buffer)
        }
        if !websocket && env. get("HTTP_UPGRADE") == Some(&"websocket".to_string()) {
            return report_error(404,&request_line, &mut stream)
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
            std::io::copy(&mut buf_reader.by_ref().take(content_len), &mut std::io::sink())?;
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
                         .current_dir(&path_translated.parent().unwrap())
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
                        thread::scope(|s| {
                            s.spawn(|| {
                                let mut buffer = [0_u8;MAX_LINE_LEN]; 
                                'serv_ep: loop {
                                    let len = match reader_stream.read(&mut buffer) {
                                        Ok(len) => if len == 0 { break } else { len },
                                        Err(_) => break,
                                    };
                                    //eprintln!("decolde {len}");
                                    let mut complete = false;
                                    let mut kind = 0u8;
                                    let mut fin_data = vec![];
                                    while !complete {
                                        let (mut data,bl_kind,last,mut extra,mask,mut mask_pos) = decode_block(&buffer[0..len]);
                                        if data.len() == 0 { break 'serv_ep} // socket close, can be 0 for ping?
                                        
                                        while extra > 0 {
                                            //eprintln!("reading {extra}");
                                            let len = match reader_stream.read(&mut buffer) {
                                                Ok(len) => if len == 0 { break 'serv_ep} else { len },
                                                Err(_) => break 'serv_ep,
                                            };
                                            //eprintln!("read only {len}");
                                            for i in 0..len {
                                                extra -= 1;
                                                data.push(buffer[i] ^ mask[mask_pos]);
                                                mask_pos = (mask_pos + 1) % 4;
                                                /*if extra == 0 {
                                                    eprintln!("there are additional bytes {}", len-1);
                                                    break
                                                }*/
                                            }
                                        }
                                        if kind == 0 {
                                            kind = bl_kind;
                                        }
                                        complete = last;
                                        fin_data.append(&mut data);
                                    }
                                    if kind != 1 { 
                                        if kind == 0x9 // ping
                                           || kind == 0xA { // pong 
                                               continue // ignore for now
                                        }
                                        if kind != 8 {
                                            LOGGER.lock().unwrap().error(&format!("block {kind} not supported yet {fin_data:?}"));
                                            continue
                                        } // otherwise close op
                                        break } // currently support only UTF8 strings, no continuation or binary data
                                    //eprintln!("all done");
                                    // TODO think how pass a block size to endpoint as: 1. in from 4 chars len, or 2. end mark like 0x00
                                    if stdin.write_all(&fin_data.as_slice()).is_err() {break};
                                    stdin.flush().unwrap();
                                    //let string = String::from_utf8_lossy(&data);
                                    //eprintln!("entered {string}");
                                }
    
                                match stdin.write_all(&[255_u8,255,255,4]) { // TODO consider also using 6 - Acknowledge
                                    Ok(()) => stdin.flush().unwrap(),
                                    Err(_) => ()
                                }
                                // forsibly kill the endpoint at a websocket disconnection
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
                            
                            let mut writer_stream = stream;
                            let mut buffer = [0_u8;MAX_LINE_LEN]; 
                            loop {
                                // TODO investigate why separation on chunks out breaks WS send
                                let Ok(len) = stdout.read(&mut buffer) else {
                                    break
                                };
                                if len == 0 { break }
                                match writer_stream.write_all(encode_block(&buffer[0..len]).as_slice()) {
                                    Err(_) => break,
                                    _ => ()
                                }
                            }
                            match writer_stream.write_all(&[0x88,0]) {
                                _ => ()
                            }
                        });
                        load.wait().unwrap();
                        return Err(Error::new(ErrorKind::BrokenPipe, "Websocket closed")) // force to close the connection and don't try to reuse
                    }
                    let mut load = Command::new(&path_translated)
                     .stdout(Stdio::piped())
                     .stdin(Stdio::piped())
                     .stderr(Stdio::piped())
                     .current_dir(&path_translated.parent().unwrap())
                     .env_clear()
                    .envs(cgi_env.unwrap()).spawn()?;
                    if let Some(extra) = extra {
                        if let Some(mut stdin) = load.stdin.take() {
                            thread::spawn(move || { // TODO consider using a separate thread pool
                                match stdin.write_all(&extra) {
                                    Err(err) => LOGGER.lock().unwrap().error(&format!{"can't write to SGI script: {err}"}),
                                    _=> () //eprintln!{"written: {}", String::from_utf8_lossy( &extra)}
                                }
                            });
                        }
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
                    let status = output.next();
                    if status.is_none() { // no headers
                        let len = output.rest_len() ;
                        stream.write_all(format!{"{protocol} 200 OK\r\nContent-Length: {len}\r\n\r\n"}.as_bytes())?;
                        if len > 0 {
                            stream.write_all(&output.rest()).unwrap()
                        }
                    } else {
                        let status = status.unwrap();
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
                        
                        while let Some(mut header)  = output.next() {
                            header = header.trim().to_string(); // consider simple trunc(2)
                            if let Some((key,val)) = header.split_once(": ") {
                                let key = key.to_lowercase();
                                if key == "location" {
                                    code_num = 302;
                                    status = format!{"{protocol} 302 Found\r\n"}
                                } else if key == "status" {
                                    if let Some((code, _)) = val.split_once(' ') {
                                        code_num = code.parse::<u16>().unwrap_or(PARSE_NUM_ERR); // should reject the request if status code unparsable
                                        status = format!{"{protocol} {val}\r\n"}
                                    }
                                }
                                if key != "content-length" && key != "status" {
                                    headers.push_str(&format!{"{header}\r\n"})
                                } 
                            }
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
                    }
                    LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" {code_num} {}",
                       SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(), output.rest_len()})
                } else {
                    let modified = fs::metadata(&path_translated)?.modified()?;
                    if since > 0 {
                        if modified.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() < since {
                            let response =
                                format!("{protocol} 304 {}\r\n\r\n", response_message(304));
                            stream.write_all(response.as_bytes())?;
                            // log
                            LOGGER.lock().unwrap().info(&format!{"{addr} -- [{:>10}] \"{request_line}\" 304 0", 
                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()});
                            return Ok(())    
                        }
                    }
                    let mut f = File::open(&path_translated)?;
                    let mut buffer = Vec::new();
                    let c_type =
                    if let Some(ref ext) = path_translated. extension() {
                        MIME.get().unwrap().get(ext.to_str().unwrap())
                    } else {None};
                    // read the whole file
                    f.read_to_end(&mut buffer)?;
                    let c_type = if c_type.is_none() {
                        "octet-stream"
                    } else { c_type.unwrap() };
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
                report_error(404,&request_line, &mut stream)?
            }
        }
    } else { // PUT DELETE HEAD TRACE OPTIONS PATCH CONNECT
        // unsupported method
        report_error(405,&request_line, &mut stream)?
    }
    if close {
        Err(Error::new(ErrorKind::ConnectionReset, "requested close"))
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
                        LOGGER.lock().unwrap().warning(&format!{"When WS_CGI and CGI set to 'true' for {path}, ENV will be cleaned as for CGI."});
                        //cgi = false
                    }
                    websocket},
            _ => &false
        };
        // TODO check for duplication web_path
        res.push(Mapping{ web_path:if *websocket {path.to_string()} else {path.to_string()  + "/"}, path: trans.into(), cgi: *cgi, websocket: *websocket })
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
    let c_type = "text/html";
    let protocol = "HTTP/1.1";
    let msg = response_message(code);
    let response =
        format!("{protocol} {code} {msg}\r\nContent-Length: {length}\r\nContent-Type: {c_type}\r\n\r\n");

    stream.write_all(response.as_bytes())?;
    stream.write_all(&contents)?;
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

fn encode_block(input: &[u8]) -> Vec<u8> { // TODO add param - last block
    let len = input.len();
    //eprintln!("encoding bl {len}");
    let mut res = vec![];
    res.reserve(len+5);
    res.push(0x81_u8); // no cont (last), text
    match len as u64 {
        1..126 => {
            res.push(len as u8); // not masked
        }
        126..0x10000_u64 => { // u16::MAX
            res.push(126 as u8); // not masked
            res.push((len >> 8) as u8);
            res.push((len & 255) as u8);
        }
        0x10000_u64..=u64::MAX => {
            res.push(127 as u8); // not masked
            #[cfg(target_pointer_width = "64")]
            {
            res.push((len >> 56 & 255) as u8);
            res.push((len >> 48 & 255) as u8);
            res.push((len >> 40 & 255) as u8);
            res.push((len >> 32 & 255) as u8);
            }
             #[cfg(target_pointer_width = "32")]
            {
            // a right solution will be split a big portion on smaller parts and send them
            // as a chain of messages, but this isn't problem for 32 bit architecture
            res.push(0u8);
            res.push(0u8);
            res.push(0u8);
            res.push(0u8);
            }
            res.push((len >> 24 & 255) as u8);
            res.push((len >> 16 & 255) as u8);
            res.push((len >> 8 & 255) as u8);
            res.push((len & 255) as u8);
        }
        _ => unreachable!("wrong {}", len) // 0 is filtered out to do not call the method
    }
    // no 4 bytes mask for server to client
    for b in input {
        res.push(*b)
    }
    res
}

fn decode_block(input: &[u8]) -> (Vec<u8>, u8, bool,u64,[u8;4],usize) {
    let buf_len = input.len();
    let mut res = Vec::new ();
    res.reserve(buf_len);
    if buf_len < 2 {
        return (res, 0, true,0,[0,0,0,0],0usize)
    }
    let last = input[0] & 0x80 == 0x80;
    let op = input[0] & 0x0f;
    let masked = input[1] & 0x80 == 0x80;
    /*if input[1] & 0x7f == 126 {
        eprintln!("len {:x} {:x}", input[2],input[3])
    }*/
    let (len, mut shift) = 
    match input[1] & 0x7f {
        len @ 0..=125 => (len as u64, 2_usize),
        126 => if buf_len > 8 {((input[3] & 255) as u64 | (input[2] as u64) << 8, 4_usize)} else {(0u64,buf_len)},
        127 => if buf_len > 14 {(input[9] as u64 | (input[8] as u64)<<8 | (input[7] as u64)<<16 |
          (input[6] as u64)<<24 | (input[4] as u64)<<32 | (input[4] as u64)<<40 | (input[3] as u64)<<48 | (input[2] as u64)<<56,
          10_usize)}
          else {(0u64,buf_len)},
        128_u8..=u8::MAX => unreachable!(),
    };
    let mut curr_mask = 0;
    let mask = if masked && buf_len > shift + 4 {
            [input[shift],input[shift+1],input[shift+2],input[shift+3]]
        } else {
            [0,0,0,0]
        };
    if masked {
        shift += 4
    }
    let extra =
        if shift+(len as usize) > buf_len {
            //eprintln!("buffer len {total_len} lesser then required {len} plus {shift}");
            if shift > buf_len {
                // TODO the algorithm should be reconsidered
                return (res, 0, true,0,[0,0,0,0],0usize)
            }
            len - (buf_len - shift) as u64
        } else {
            //eprintln!("buffer len {total_len} >= {len} + {shift}");
            0
        };

    if len > 0 && buf_len > shift  {
        for i in shift..buf_len {
            res.push(input[i] ^ mask[curr_mask]);
            curr_mask = (curr_mask + 1) % 4
        }
    }
    (res, op, last, extra,mask,curr_mask)
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
                    return Some(String::from_utf8(self.load[start..self.pos-1].to_vec()).unwrap())
                }
            } else { met = false }
            if self.load[self.pos] == b'\r' { met = true; }
            self.pos += 1
        }
        self.pos = start;
        None
    }
    
    fn rest_len(&mut self) -> usize {
        if self.load.len() == 0 {
            0
        } else {
            self.load.len() - self.pos - 1
        }
    }
    
    fn rest(&mut self) -> Vec<u8> {
        self.load[self.pos+1..].to_vec()
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