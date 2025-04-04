extern crate simtpool;
extern crate simjson;
extern crate rslash;
use std::{
    fs::{self,File},
    io::{prelude::*, BufReader, self},
    net::{TcpListener, TcpStream,ToSocketAddrs},
    thread,
    sync::{atomic::{AtomicBool,Ordering}, Arc},
    path::{Path,MAIN_SEPARATOR_STR,PathBuf},
    collections::HashMap,
    process::{Stdio,Command},
};
use simtpool::ThreadPool;
use simjson::JsonData::{Num,Text,Data,Arr,Bool,self};

struct Mapping {
    web_path: String,
    path: String,
    cgi: bool
}

struct CgiOut {
    load: Vec<u8>,
    pos: usize,
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
    let Some(tp) = env.get("threads") else {
        eprintln!{"No number of threads configured"}
        return
    };
    let Num(tp) = tp else {
        eprintln!{"number of threads not a number"}
        return
    };
    let Some(bind) = env.get("bind") else {
        eprintln!{"No binded addr is specified"}
        return
    };
    let Text(bind) = bind else {
        eprintln!{"No corect bind address configured"}
        return
    };
    let Some(port) = env.get("port") else {
        eprintln!{"No port number configured"}
        return
    };
    let Num(port) = port else {
        eprintln!{"No a number port number configured"}
        return
    };
    
    let Some(mapping) = env.get("mapping") else {
        eprintln!{"No mapping configured"}
        return
    };
    let Arr(mapping) = mapping else {
        eprintln!{"Incorrect mapping configured"}
        return
    };
    
    let tp = ThreadPool::new(*tp as usize);

    let listener = TcpListener::bind(format!{"{bind}:{port}"}).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_one = stop.clone();
    let mapping = Arc::new(read_mapping(mapping));
    
    thread::spawn(move || {
            let mut input = String::new();
            loop {
                io::stdin().read_line(&mut input).expect("Failed to read line");
                if input.starts_with("q") {
                    stop_one.store(true, Ordering::SeqCst);
                    break
                }
            }
        });
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mapping = Arc::clone(&mapping);
        tp.execute(move || {
            eprintln!{"request from {:?}", stream.peer_addr()}
            handle_connection(stream, &mapping) 
        });
        if stop.load(Ordering::SeqCst) { break }
    }
    drop(tp)
}

fn handle_connection(mut stream: TcpStream, mapping: &Vec<Mapping>) {
    let buf_reader = BufReader::new(&stream);
    let mut headers = buf_reader.lines();
    /*let Ok(headers) = headers else {
        eprintln!{"bad request"}
        return
    };*/
    if let Some(request_line) = headers.next() {
        let Ok(request_line) = request_line else {
            eprintln!{"bad request"}
            return
        };
        let mut parts  = request_line.splitn(3, ' '); // split_whitespace
        //  TODO bad request instead of unwrap
        let method = parts.next().unwrap();
        let mut path = parts.next().unwrap().to_string();
        let protocol = parts.next().unwrap();
        let query = match path.find('?') {
            Some(qp) => {
                let temp = &path[qp+1..].to_string();
                path = path[0..qp].to_string();
                temp.clone()
            }
            None => "".to_string()
        };
        if path.chars().rev().nth(0) == Some('/') {
                path += "index.html"//.to_string()
        }
        let mut path_translated = None;
        let mut cgi = false;
        let mut name = "".to_string();
        let mut path_info = None;
        for e in mapping {
            if path.starts_with(&e.web_path) {
                cgi = e.cgi;
                if cgi {
                    let mut cgi_file = PathBuf::new();
                    cgi_file.push(e.path.clone());
                    name = path[e.web_path.len()..].to_string();
                    path_info = if let Some(pos) = name.find('/') {
                        let temp = name[pos..].to_string();
                        name = name[..pos].to_string();
                        if cfg!(windows) {
                        name = name + ".exe";}
                        Some(temp)
                    } else {
                        None
                    };
                    path_translated = Some(rslash::adjust_separator(e.path.clone() + MAIN_SEPARATOR_STR + &name))
                } else {
                    path_translated = Some(rslash::adjust_separator(e.path.clone() + MAIN_SEPARATOR_STR + &path[e.web_path.len()..]));
                    eprintln!{"mapping found as {path_translated:?}"}
                }
                break
            } else { println!{"path {path} not start with {}", e.web_path} }
        }
        //cgi = true;
        let mut content_len = 0_u64;
        let cgi_env = if cgi {
            let mut env = HashMap::new();
            env.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
            env.insert("QUERY_STRING".to_string(), query);
            env.insert("REMOTE_ADDR".to_string(), stream.peer_addr().unwrap().to_string()); // TODO add handling of an error
            env.insert("REMOTE_HOST".to_string(), stream.peer_addr().unwrap().to_socket_addrs().unwrap().next().unwrap().to_string());
            env.insert("REQUEST_METHOD".to_string(), method.to_string());
            env.insert("SERVER_PROTOCOL".to_string(), protocol.to_string());
            env.insert("SERVER_SOFTWARE".to_string(), "SimHTTP/1.01".to_string());
            if let Some(path_info) = path_info {
                 env.insert("PATH_INFO".to_string(), path_info);
            }
            if let Some(ref path_translated) = path_translated {
                env.insert("PATH_TRANSLATED".to_string(), path_translated.into());
            }
            if !name.is_empty() {
                env.insert("SCRIPT_NAME".to_string(), name);
            }
            while let Some(header) = headers.next() {
                let header = header.unwrap();
                
                if header.is_empty() {
                   break
                }
                println!{"heare: {header}"}
                if let Some((key,val)) = header.split_once(": ") {
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
                            //content_len = val.parse::<u64>().unwrap(); // TODO error hundling
                            env.insert("CONTENT_LENGTH".to_string(), val.trim().to_string());
                        }
                        "content-type" => {
                            env.insert("CONTENT_TYPE".to_string(), val.trim().to_string());
                        }
                        "authorization" => {
                            env.insert("AUTH_TYPE".to_string(), val.to_string());
                        }
                        _ => ()
                    }
                }
            }
            if content_len > 0 {
                let mut buffer = vec![0u8; content_len as usize];
                if let Ok(_) = &stream.read_exact(&mut buffer) {
                    env.insert("QUERY_STRING".to_string(), String::from_utf8_lossy(&buffer).into()); // more likelly ANSI
                } 
            }
            Some(env)
        } else { 
            while let Some(header) = headers.next() {
                let header = header.unwrap();
                println!{"header: {header}"}
                if header.is_empty() {
                   
                   break
                }
                if let Some((key,val)) = header.split_once(": ") {
                     let key = key.to_lowercase();
                    let key = key.as_str();
                    match key {
                        "content-length" => {  
                            content_len = val.parse::<u64>().unwrap(); // TODO error hundling
                        }
                        &_ => ()
                    }
                }
                
            }
            if content_len > 0 {
                let mut buffer = vec![0u8; content_len as usize];
                let _ = &stream.read_exact(&mut buffer);
            }
            None };
        
        if method == "GET" {
            println!{"servicing get"}
             if cgi {
                let load = Command::new(&path_translated.unwrap())
                 .stdin(Stdio::null())
                 .stderr(Stdio::inherit())
                 .env_clear()
                .envs(cgi_env.unwrap()).output();
                let mut output = CgiOut{load:load.unwrap().stdout, pos:0};
                let status = output.next();
                if status.is_none() {
                    let len = output.rest_len() ;
                    stream.write_all(format!{"{protocol} 200 OK\r\nContent-Length: {len}\r\n\r\n"}.as_bytes()).unwrap();
                    
                    if len > 0 {
                        stream.write_all(&output.rest()).unwrap()
                    }
                } else {
                    let status = status.unwrap();
                    if status.find(':') . is_some() {
                        stream.write_all(format!{"{protocol} 200 OK\r\n{status}\r\n"}.as_bytes()).unwrap();
                    } else {
                        
                        let (code, msg) = 
                        match status.split_once(' ') {
                            Some((code,msg)) => (code.to_string(),msg.to_string()),
                            None => {
                                match status.as_str() {
                                    "200" => ("200".to_string(),"OK".to_string()),
                                    _ => (status.clone(),format!{"ERROR {status}"})
                                }
                            }
                        };
                        stream.write_all(format!{"{protocol} {code} {msg}\r\n"}.as_bytes()).unwrap();
                    }
                    while let Some(header)  = output.next() {
                        stream.write_all(format!{"{header}\r\n"}.as_bytes()).unwrap()
                    }
                    let len = output.rest_len() ;
                    stream.write_all(format!{"Content-Length: {len}\r\n\r\n"}.as_bytes()).unwrap();
                    
                    if len > 0 {
                        stream.write_all(&output.rest()).unwrap();
                    }
                }
            } else {
            
            let (status_line,length,contents) =
            if path_translated.is_none() || !Path::new(&path_translated.as_ref().unwrap()).is_file() {
                let contents = include_str!{"404.html"};
                let length = contents.len();
                (format!{"{protocol} 404 NOT FOUND"}, length, contents.to_string())
            } else {
               
                let mut f = File::open(&path_translated.unwrap()).unwrap( );
                let mut buffer = Vec::new();

                // read the whole file
                f.read_to_end(&mut buffer).unwrap();
                let contents = String::from_utf8_lossy(&buffer);
                let length = contents.len();
                (format!{"{protocol} 200 OK"}, length, contents.to_string())
            };
        
            let response =
                format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");
        
            stream.write_all(response.as_bytes()).unwrap();
            }
        }
    };
}

fn read_mapping(mapping: &Vec<JsonData>) -> Vec<Mapping> {
    let mut res = Vec::new();
    for e in mapping {
        let Data(e) = e else { continue };
        let path = e.get("path");
        
        let Some(path) = path else { continue; };
        let Text(path) = path else { continue; };
        let trans = e.get("translated");
        
        let Some(trans) = trans else { continue };
        let Text(trans)  = trans else { continue };
        let cgi = match e.get("CGI") {
            None => false,
            Some(cgi) => * match cgi {
                Bool(cgi) => cgi,
                _ => &false
            }
        };
        res.push(Mapping{ web_path:path.to_string()  + "/", path: trans.into(), cgi: cgi })
    }
    res.sort_by(|a, b| b.web_path.len().cmp(&a.web_path.len()));
    res
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
        self.load.len() - self.pos
    }
    
    fn rest(&mut self) -> Vec<u8> {
        self.load[self.pos..].to_vec()
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