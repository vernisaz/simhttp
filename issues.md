# Known issues

1. It's practically impossible to stop the server gracefully. There are some solutions, like
[nblistener](https://github.com/garypen/nblistener/tree/master), however it looks complicated.
Unfotunately interruptable isn't supported for *TcpListener* by Rust. There is some recomendation to obtain OS
level of **TcpListener** using *as_raw_fd()* on Unix and *as_raw_socket()* pointers and then call *shutdown()* and
*WSAshutdown()* correspondingly.
2. Websocket closing issue seems resolved.