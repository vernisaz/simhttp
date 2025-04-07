# SimHttp - Rust web server
## Purpose
It is a personal web server for Rust web appllications. It supports servicing files and execution 
files supporting [CGI](https://www.rfc-editor.org/rfc/rfc3875). 
## Building
RustBee scripting file is provided to build the server. There are 3 dependencies from
microlibraries crates pool. They should be cloned and built first.
- [RightSlash](https://github.com/vernisaz/right_slash)
- [SimJSON](https://github.com/vernisaz/simjson)
- [SimThreadPool](https://github.com/vernisaz/simtpool)
 


## Configuring
One JSON file is used for configuring the server. The file has to be in the same directory as the server.

## Running
Just execute its executable file.

## Status
Currently the server in an active development. However is seems already fully functional, so you can try it.
