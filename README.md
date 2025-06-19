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

## usage

```bash
git clone https://github.com/MeexReay/sRAC.git; cd sRAC
cargo run -- -H rac://127.0.0.1:42666
```

## roadmap

- [x] WRAC protocol
- [x] RACS protocol
- [x] Proxy-mode
- [ ] Notifications by ip (private messages)
- [ ] Server commands

## license

This project is licensed under the WTFPL. Do what the fuck you want to. 