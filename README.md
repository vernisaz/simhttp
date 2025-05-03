# SimHttp - Rust web server (TRWS)
## Purpose
It is a personal web server for Rust web appllications. It supports servicing and executing 
files supporting [CGI](https://www.rfc-editor.org/rfc/rfc3875).
## History
I implemented TJWS back in 1999. It had a purpose to run and debug small web applications. 
However an interest to Java dropped recent years, so I decided to use Rust for the purpose.

TRWS - is succesor of TJWS, but instead of servlets it runs CGI web applications which can be written in
any language including Rust. It also supports websocket endpoints. They can be application
supporting the standard OS piping. Such approach is more beneficial than offered by Rocket A web framework for Rust gear Rust. 

## Building
RustBee scripting file is provided to build the server. There are 4 dependencies from
microlibraries crates pool. They should be cloned and built first.
- [RightSlash](https://github.com/vernisaz/right_slash)
- [SimJSON](https://github.com/vernisaz/simjson)
- [SimThreadPool](https://github.com/vernisaz/simtpool)
- [SimWEb](https://github.com/vernisaz/simweb) 

## Configuring
One JSON file is used for configuring the server. The file has to be in the same directory as the server.

## Running
Just execute its executable file. Press 'q' for stop.

## Websocket
The server provides a limited support of websocket protocol as WS-CGI.

## Status
Current version is SimHTTP/1.11b32. It's a beta version.
