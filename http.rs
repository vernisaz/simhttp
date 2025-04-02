extern crate simtpool;
extern crate simjson;
use std::{
    fs,
    io::{prelude::*, BufReader, self},
    net::{TcpListener, TcpStream},
    thread,
    sync::{atomic::{AtomicBool,Ordering}, Arc},
    path::{Path,MAIN_SEPARATOR_STR},
};
use simtpool::ThreadPool;
use simjson::JsonData::{Num,Text,Data,Arr,self};

struct Mapping {
    web_path: String,
    path: String
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
        let method = parts.next().unwrap();
        let mut path = parts.next().unwrap().to_string();
        let protocol = parts.next().unwrap();
        if method == "GET" {
            if path.chars().rev().nth(0) == Some('/') {
                path += "index.html"//.to_string()
            }
            let mut path_translated = None;
            for e in mapping {
                if path.starts_with(&e.web_path) {
                    path_translated = Some(e.path.clone() + MAIN_SEPARATOR_STR + &path[e.web_path.len()..]);
                    eprintln!{"mapping found as {path_translated:?}"}
                }
            }
            
            let (status_line,length,contents) =
            if path_translated.is_none() || !Path::new(&path_translated.as_ref().unwrap()).is_file() {
                let contents = include_str!{"404.html"};
                let length = contents.len();
                (format!{"{protocol} 404 NOT FOUND"}, length, contents.to_string())
            } else {
                let contents = fs::read_to_string(&path_translated.unwrap()).unwrap();
                let length = contents.len();
                (format!{"{protocol} 200 OK"}, length, contents)
            };
        
            let response =
                format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");
        
            stream.write_all(response.as_bytes()).unwrap();
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
        res.push(Mapping{ web_path:path.into(), path: trans.into() })
    }
    res.sort_by(|a, b| a.web_path.len().cmp(&b.web_path.len()));
    res
}