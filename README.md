# SimHttp - Rust web server (aka TRWS)
## Purpose
It is a web server for personal Rust web applications. It supports servicing files and executing 
 [CGI](https://www.rfc-editor.org/rfc/rfc3875) scripts.

## History
I've implemented TJWS back in 1999. It has the purpose to run and debug Java web applications. 
However an interest to Java dropped recent years, so I decided to implement a similar purpose server in Rust.

TRWS - is a successor of TJWS, but instead of servlets it runs CGI web applications which can be written in
any language including Rust. It also supports websocket endpoints. They are applications supporting OS piping.
Such approach is more beneficial than offered by other
Rust web servers, because doesn't require to rebuild the entire server at every serviced app change. 

Obviously SimHttp is CI/CD friendly.

A serviced Rust app can run as in CLI mode as in a web mode without any change.

The server is perfectly suitable for an embedded development. You can deploy it on an embedded platform. CGI endpoints can be
developed in C or Rust.

## Building
A RustBee script file is provided to build the server. There are 4 dependencies from the
micro libraries (crate) pool. The repositories should be cloned and built first.

- [scripts](https://github.com/vernisaz/simscript) it's only scripts required to build crates below
- [RightSlash](https://github.com/vernisaz/right_slash)
- [SimJSON](https://github.com/vernisaz/simjson)
- [SimThreadPool](https://github.com/vernisaz/simtpool)
- [SimWeb](https://github.com/vernisaz/simweb) -> requires [SimTime](https://github.com/vernisaz/simtime)


The directory where all *rlib* resides has to be specified in *crate_dir* variable of
[bee.7b](https://github.com/vernisaz/simhttp/blob/master/bee.7b) script. 
It has to be presented before building crates and the server.

The following directories structure is expected to build the server
```
├─projects┐
│   ┌─────┘
│   ....
│   ├─simscript
│   ├─crates
│   ├─simhttp
│   ├─right_slash
│   ├─simjson
│   ├─simtpool
│   ├─simweb
│   ├─simtime
│   .....
....
```

The server is built by executing _rb_ in its repository.

## Configuring
One JSON file is used for configuring the server. The file has to be in the current working directory the server ran from.
An example of [env.conf](https://github.com/vernisaz/simhttp/blob/master/env.conf) file is self describing.
The same executable of the server can be used for multiple configurations. Obviously the listening port or/and the binding
address have to be different in the configurations.

## Running
Just launch **simhttp**. Press 'q' for stop. (See a note in the [issues](https://github.com/vernisaz/simhttp/blob/master/issues.md))

If you run _simhttp_ in a *SSH* session and want to keep it running after the session gets closed, then use -
`"no terminal": true` property in the configuration and launch it with ending `&`. The server will be less verbose in the case.
If you still want to see an occasional server output to
the console, then run it using _nohup_ utility as (`"no terminal": false`):

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

[bee.7b](./bee.7b) contains details how to run it in the background under Windows.

## Websocket
The server provides a limited support of WebSocket protocol as WS-CGI. Only UTF-8 string packets are supported.

## How to compare it to miniserve and other Rust webservers
If you didn't check [miniserve](https://github.com/svenstaro/miniserve/tree/master) yet, then do it now. More likely you will be satisfied with it.
 Major difference of the _TRWS_ that it can be extended by CGI scripts
and CGI websocket endpoints. For example, I implemented [TOTP](https://github.com/vernisaz/simtotp) with web interface,
I couldn't do without _simhttp_. Simhttp is decoupled from deployed Rust applications, and you can deploy them without any change
of the server.

## Status
Current version is SimHTTP/1.22b55. It's a beta version.
