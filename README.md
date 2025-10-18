# sRAC
simple server for RAC

## features

- RACv2.0 and WRACv2.0 protocols
- SSL encryption (via rustls)
- messages limits by size
- splash message
- message sanitizing (removes all shit)
- auth-only mode and accounts
- messages saving into file
- register and message timeouts
- multiple listeners on one server

## examples of usage

### normal rac server

run normal rac server without encryption and websockets

```bash
cargo run -- -H 127.0.0.1:42666
```

### self-signed wracs server

enables wracs usign RAC url (wracs://ip:port, s stands for secure and w for websocket) and uses self-signed certs for encryption

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
cargo run -- -H wracs://127.0.0.1:42666 --ssl-key server.key --ssl-cert server.crt
```

[read more about rac-url](https://github.com/MeexReay/bRAC/blob/main/docs/url.md)

### multiple listeners on one server

runs multiple listeners on different protocols but uses only one server, so you dont need to use proxy-mode

```bash
cargo run -- \
  -H wrac://127.0.0.1 rac://127.0.0.1 wracs://127.0.0.1 racs://127.0.0.1 \
  --ssl-key server.key --ssl-cert server.crt
```

or you can write separately:

```bash
cargo run -- \
  -H rac://127.0.0.1 \
  -H racs://127.0.0.1 \
  -H wrac://127.0.0.1 \
  -H wracs://127.0.0.1 \
  --ssl-key server.key --ssl-cert server.crt
```

### proxy-mode

proxy that redirects data from rac://127.0.0.1 and wrac://127.0.0.1 to wracs://127.0.0.1. keep in mind that target server will only see proxy's ip

```bash
cargo run -- \
  -H rac://127.0.0.1 \
  -H wrac://127.0.0.1 \
  -P wracs://127.0.0.1
```

### disabled proxy-mode

proxy-mode brings with it very massive bRAC code (without GUI part, but anyway), so it would be great to not compile it

```bash
cargo run --no-default-features -- -H rac://127.0.0.1:42666
```

## roadmap

- [x] WRAC protocol
- [x] RACS protocol
- [x] Proxy-mode
- [ ] Notifications by ip (private messages)
- [ ] Server commands

## license

This project is licensed under the WTFPL. Do what the fuck you want to. 
