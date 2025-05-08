# SimHttp - Rust web server (TRWS)
## Purpose
It is a personal web server for Rust web applications. It supports servicing and executing 
files supporting [CGI](https://www.rfc-editor.org/rfc/rfc3875).
## History
I've implemented TJWS back in 1999. It has the purpose to run and debug small web applications. 
However the interest to Java dropped recent years, so I decided to use Rust for the server.

TRWS - is a successor of TJWS, but instead of servlets it runs CGI web applications which can be written in
any language including Rust. It also supports websocket endpoints. They can be applications
supporting the standard OS piping. Such approach is more beneficial than offered by Rocket A web framework for Rust gear Rust. 
Although web applications can look not so slick as when used the Rocket. If you use **hyper**, then you need to
build a server for the particular use case. SimHttp uses a lose coupling approach when you do not need to rebuild a server for every case.
It's also CI/CD friendly.
## Building
RustBee scripting file is provided to build the server. There are 4 dependencies from the
micro libraries crates pool. They should be cloned and built first.
- [RightSlash](https://github.com/vernisaz/right_slash)
- [SimJSON](https://github.com/vernisaz/simjson)
- [SimThreadPool](https://github.com/vernisaz/simtpool)
- [SimWEb](https://github.com/vernisaz/simweb) 

## Configuring
One JSON file is used for configuring the server. The file has to be in the same directory as the server.
The configuration syntax is self describing. 

## Running
Just execute its executable file. Press 'q' for stop.

## Websocket
The server provides a limited support of WebSocket protocol as WS-CGI.

## Status
Current version is SimHTTP/1.11b33. It's a beta version.
