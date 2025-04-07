extern crate simtpool;
extern crate simjson;
extern crate rslash;
use std::{
    fs::{self,File},
    io::{prelude::*, Error, ErrorKind, BufReader, self},
    net::{TcpListener, TcpStream,ToSocketAddrs},
    thread,
    sync::{atomic::{AtomicBool,Ordering}, Arc},
    path::{Path,MAIN_SEPARATOR_STR,PathBuf},
    collections::HashMap,
    process::{Stdio,Command},
    time::{SystemTime,UNIX_EPOCH},
    env,
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
    let mut mime2 = HashMap::new(); 
    if let Some(mime) = env.get("mime") {
        if let Arr(mime) = mime {
            
            for el in mime {
                if let Data(el) = el {
                    if let Some(en) = el.get("ext") {
                        if let Text(en) = en {
                            if let Some(val) = el.get("type") {
                                if let Text(val) = val {
                                    mime2.insert(en.to_string(),val.to_string());
                                }
                            }
                        }
                    }
                }
            } 
        }
    };
    let mime = Arc::new(mime2);
    
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
                    //println!{"Stop accepted"}
                    break
                }
                input.clear()
            }
        });
    
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mapping = Arc::clone(&mapping);
        let mime = Arc::clone(&mime);
        let stop_two = stop.clone();
        tp.execute(move || {
            while handle_connection(&stream, &mapping, &mime) . is_ok() {
                if stop_two.load(Ordering::SeqCst) { break }
            }
        });
        //println!{"Checking Stop"}
        if stop.load(Ordering::SeqCst) { break }
    }
    println!{"Stopping the server..."}
    drop(tp)
}

fn handle_connection(mut stream: &TcpStream, mapping: &Vec<Mapping>, mime: &HashMap<String,String>) -> io::Result<()> {
    let mut buf_reader = BufReader::new(stream);
    let mut line = String::new();
    //let lines = buf_reader.lines(); // may still work
    let len = buf_reader.read_line(&mut line)?;
    if len < 10 { // http/1.x ...
        eprintln!{"bad request"}
        return Err(Error::new(ErrorKind::Other, "no data"))
    }
    line.truncate(len-2); // \r\n
    let request_line = line.clone();
    let mut parts  = request_line.splitn(3, ' '); // split_whitespace
    let method = parts.next().unwrap();
    let mut path = parts.next().unwrap().to_string();
    let protocol = parts.next().unwrap();
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
                    Some(temp)
                } else {
                    None
                };
                if cfg!(windows) {
                    name = name + ".exe";}
                path_translated = Some(rslash::adjust_separator(e.path.clone() + MAIN_SEPARATOR_STR + &name))
            } else {
                if path.chars().rev().nth(0) == Some('/') {
                    path += "index.html"
                }
                path_translated = Some(rslash::adjust_separator(e.path.clone() + MAIN_SEPARATOR_STR + &path[e.web_path.len()..]));
                //eprintln!{"mapping found as {path_translated:?}"}
            }
            break
        } //else { println!{"path {path} not start with {}", e.web_path} }
    }
    
    let mut content_len = 0_u64;
    let mut extra = None;
    let cgi_env = if cgi {
        let mut env : HashMap<String, String> =
            env::vars().filter(|&(ref k, _)|
             k != "PATH"
         ).collect();
        env.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        env.insert("QUERY_STRING".to_string(), query);
        env.insert("REMOTE_ADDR".to_string(), stream.peer_addr().unwrap().to_string()); // TODO add handling of an error
        env.insert("REMOTE_HOST".to_string(), stream.peer_addr().unwrap().to_socket_addrs().unwrap().next().unwrap().to_string());
        env.insert("REQUEST_METHOD".to_string(), method.to_string());
        env.insert("SERVER_PROTOCOL".to_string(), protocol.to_string());
        env.insert("SERVER_SOFTWARE".to_string(), "SimHTTP/1.01".to_string());
        if let Some(ref path_info) = path_info {
             env.insert("PATH_INFO".to_string(), path_info.into());
        }
        if let Some(ref path_translated) = path_translated {
            let mut path_translated = PathBuf::from(&path_translated);
            path_translated.pop();
            let mut path_translated = path_translated.as_path().canonicalize().unwrap();
            if !path_translated.is_absolute() {
                 path_translated = env::current_dir()?.join(path_translated)
            }
            let path_translated = if let Some(ref path_info) = path_info {
                rslash::adjust_separator(path_translated.to_str().unwrap().to_string() + &path_info)
            } else {
                path_translated.to_str().unwrap().to_string()
            };
            
            env.insert("PATH_TRANSLATED".to_string(), path_translated);
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
                        content_len = val.parse::<u64>().unwrap(); // TODO error hundling
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
            }
            line.clear()
        }
        if !env.contains_key("CONTENT_TYPE") {
            env.insert("CONTENT_TYPE".to_string(), "text/html".to_string());
        }
        // application/x-www-form-urlencoded
        if content_len > 0 {
            let mut buffer = vec![0u8; content_len as usize];
             buf_reader.read_exact(&mut buffer)?;
            //println!{"input:-> {}", String::from_utf8_lossy( &buffer)}
            extra = Some(buffer)
        }
        Some(env)
    } else { 
        while 2 < buf_reader.read_line(&mut line)? {
            line.truncate(line.len()-2); // \r\n
            //eprintln!{"header: {line}"}
            if let Some((key,val)) = line.split_once(": ") {
                 let key = key.to_lowercase();
                let key = key.as_str();
                match key {
                    "content-length" => {  
                        content_len = val.parse::<u64>().unwrap(); // TODO error hundling
                    }
                    /*"location" => {
                    }*/
                    &_ => ()
                }
            }
            
        }
        if content_len > 0 {
            std::io::copy(&mut buf_reader.by_ref().take(content_len), &mut std::io::sink())?;
            //buf_reader.seek_relative(content_len)?
        }
        None };
        
        if method == "GET" || method == "POST" {
           // eprintln!{"servicing {method} to {path_translated:?}"}
             if cgi {
                let path_translated = PathBuf::from(&path_translated.unwrap());
                let mut load = Command::new(&path_translated)
                 .stdout(Stdio::piped())
                 .stdin(Stdio::piped())
                 .stderr(Stdio::inherit())
                 .current_dir(&path_translated.parent().unwrap())
                 .env_clear()
                .envs(cgi_env.unwrap()).spawn()?;
                
                let mut stdin = load.stdin.take().expect("Failed to open stdin");
                thread::spawn(move || {
                    if let Some(extra) = extra {
                        stdin.write_all(&extra).expect("Failed to write to stdin");
                        //eprintln!{"written: {}", String::from_utf8_lossy( &extra)}
                    }
                });

                let output = load.wait_with_output()?;
               // println!{"load {}", String::from_utf8_lossy( &output.stdout)}
                let mut output = CgiOut{load:output.stdout, pos:0};
                let mut code_num = 200;
                let status = output.next();
                if status.is_none() { // no headers
                    let len = output.rest_len() ;
                    stream.write_all(format!{"{protocol} 200 OK\r\nContent-Length: {len}\r\n\r\n"}.as_bytes()).unwrap();
                    if len > 0 {
                        stream.write_all(&output.rest()).unwrap()
                    }
                } else {
                    let status = status.unwrap();
                    let mut headers = String::new();
                    let mut status =
                    if status.find(':') . is_some() {
                        if let Some((key,val)) = status.split_once(": ") {
                            let key = key.to_lowercase();
                            if key != "content-length" {
                                headers.push_str(&format!{"{status}\r\n"});
                            } else {
                                
                            }
                            if key == "location" {
                                code_num = 302;
                                format!{"{protocol} 302 Found\r\n"}
                            } else if key == "status" {
                                if let Some((code, _)) = val.split_once(" ") {
                                    code_num = code.parse::<u16>().unwrap();
                                }
                                format!{"{protocol} {val}\r\n"}
                            } else {
                                format!{"{protocol} 200 OK\r\n"}
                            }
                        } else { // never
                            format!{"{protocol} 200 OK\r\n"}
                        }
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
                        code_num = code.parse::<u16>().unwrap();
                        format!{"{protocol} {code} {msg}\r\n"}
                    };
                    
                    while let Some(header)  = output.next() {
                        if let Some((key,val)) = header.split_once(": ") {
                            let key = key.to_lowercase();
                            if key == "location" {
                                code_num = 302;
                                status = format!{"{protocol} 302 Found\r\n"}
                            } else if key == "status" {
                                if let Some((code, _)) = val.split_once(" ") {
                                    code_num = code.parse::<u16>().unwrap();
                                    status = format!{"{protocol} {val}\r\n"}
                                }
                            }
                            if key != "content-length" {
                                headers.push_str(&format!{"{header}\r\n"})
                            } else {
                                
                            }
                        }
                        
                    }
                    stream.write_all(status.as_bytes())?;
                    stream.write_all(headers.as_bytes())?;
                    let len = output.rest_len() ; // why not content-length ?
                    //eprintln!{"{status}\n{headers}Content-Length: {len}\r\n\r\n"}
                    stream.write_all(format!{"Content-Length: {len}\r\n\r\n"}.as_bytes())?;
                    if len > 0 {
                        stream.write_all(&output.rest())?;
                        //eprintln!{"{:?}", String::from_utf8_lossy(&output.rest())}
                    }
                }
                println!{"{} -- [{:>10}] \"{request_line}\" {code_num} {}", stream.peer_addr().unwrap().to_string(),
                   SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(), output.rest_len()}
            } else {
                let (status_line,code,length,c_type,contents) =
                if path_translated.is_none() || !Path::new(&path_translated.as_ref().unwrap()).is_file() {
                    let contents = include_str!{"404.html"};
                    let contents = contents.as_bytes();
                    let length = contents.len();
                    let c_type = "text/html";
                    (format!{"{protocol} 404 NOT FOUND"}, 404, length, c_type, contents.to_vec())
                } else {
                    let path_translated = path_translated.unwrap();
                    let mut f = File::open(&path_translated)?;
                    let mut buffer = Vec::new();
                    let c_type =
                    if let Some(pos) = path_translated.rfind('.') {
                        mime.get(&path_translated[pos+1..])
                    } else {None};
                    // read the whole file
                    f.read_to_end(&mut buffer)?;
                    let c_type = if c_type.is_none() {
                        "octet-stream"
                    } else { c_type.unwrap() };
                    let length = buffer.len();
                    (format!{"{protocol} 200 OK"}, 200, length, c_type, buffer)
                };
            
                let response =
                    format!("{status_line}\r\nContent-Length: {length}\r\nContent-Type: {c_type}\r\n\r\n");
            
                stream.write_all(response.as_bytes())?;
                stream.write_all(&contents)?;
                // log
                println!{"{} -- [{:>10}] \"{request_line}\" {code} {length}", stream.peer_addr().unwrap().to_string(),
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()}
            }
        }
    Ok(())
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
        self.load.len() - self.pos - 1
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