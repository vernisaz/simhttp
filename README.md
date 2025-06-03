# SimHttp - Rust web server (TRWS)
## Purpose
It is a personal web server for Rust web applications. It supports servicing and executing 
files supporting [CGI](https://www.rfc-editor.org/rfc/rfc3875).
## History
I've implemented TJWS back in 1999. It has the purpose to run and debug small web applications. 
However an interest to Java dropped recent years, so I decided to use Rust for a similar server.

TRWS - is a successor of TJWS, but instead of servlets it runs CGI web applications which can be written in
any language including Rust. It also supports websocket endpoints. They can be applications
supporting the standard OS piping. Such approach is more beneficial than offered by Rocket A web framework for Rust gear Rust. 
Although web applications can look not so slick as when used the Rocket. Since SimHttp uses a lose coupling approach when
you do not need to rebuild the server for every case, it is more beneficial against such Rust servers as
**hyper**. 
Obviosly SimHttp is CI/CD friendly.

## Building
A RustBee script file is provided to build the server. There are 4 dependencies from the
micro libraries (crate) pool. They should be cloned and built first.
- [RightSlash](https://github.com/vernisaz/right_slash)
- [SimJSON](https://github.com/vernisaz/simjson)
- [SimThreadPool](https://github.com/vernisaz/simtpool)
- [SimWEb](https://github.com/vernisaz/simweb) -> requires [SimTime](https://github.com/vernisaz/simtime)

The directory where all *rlib* resides has to be specified in *crate_dir* variable of
[bee.7b](https://github.com/vernisaz/simhttp/blob/master/bee.7b) script.

## Configuring
One JSON file is used for configuring the server. The file has to be in the same directory as the server executable.
An example of [config](https://github.com/vernisaz/simhttp/blob/master/env.conf) file is self describing. 

## Running
Just launch **simhttp**. Press 'q' for stop. (See a note in the [issues](https://github.com/vernisaz/simhttp/blob/master/issues.md))

## Websocket
The server provides a limited support of WebSocket protocol as WS-CGI.

## Status
Current version is SimHTTP/1.12b42. It's a beta version.
