# SimHttp - Rust web server (TRWS)
## Purpose
It is a personal web server for Rust web applications. It supports servicing and executing 
files supporting [CGI](https://www.rfc-editor.org/rfc/rfc3875).
## History
I've implemented TJWS back in 1999. It has the purpose to run and debug small web applications. 
However an interest to Java dropped recent years, so I decided to use Rust for a similar server.

TRWS - is a successor of TJWS, but instead of servlets it runs CGI web applications which can be written in
any language including Rust. It also supports websocket endpoints. They can be applications
supporting the standard OS piping. Such approach is more beneficial than offered by other
Rust web servers, because doesn't require to rebuild the entire server at every servced app change. 

Obviosly SimHttp is CI/CD friendly.

A serviced Rust app can run as in CLI mode as in a web mode without any change.

The server is perfectly suitable for embedded development. You can deploy it on an embeded platform. CGI endpoints can be
developed in C or Rust.

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

If you run _simhttp_ in a *SSH* session and want to keep it running after the session gets closed, then use:

> nohup simhttp &

or as an alternative, run

> screen

and then,

- Run _simhttp_: within the screen session.
- Detach the screen session: Press Ctrl-A then Ctrl-D.
- Log out: of the SSH session.
- Reattach the screen session: later:

> screen -r

*tmux* can be also used similarly to the _screen_.

You can also specify `"no terminal": true'` in _.conf_ file, and then launch the _simhttp_
with ending `&`. But the server will be less verbosive in the case.

## Websocket
The server provides a limited support of WebSocket protocol as WS-CGI.

## How to compare it to miniserve
If you didn't check [miniserve](https://github.com/svenstaro/miniserve/tree/master) yet, then do it now. More likely you will be satisfied with it.
_miniserve_ reminds me [TJWS](https://tjws.sf.net) I implemented in the last century. Major difference of the _TRWS_ that it can be extended by CGI scripts
and CGI websocket endpoints.

## Status
Current version is SimHTTP/1.12b47. It's a beta version.
