# sRAC
simple server for RAC

## Usage

```bash
git clone https://github.com/MeexReay/sRAC
cd sRAC
cargo run -- -H 127.0.0.1:42666
```

### My server config

```bash
cargo run -- \
  --host 127.0.0.1:42666 \
  --splash "please register (/register and /login commands in bRAC)" \
  --messages-file "messages.txt" \
  --accounts-file "accounts.txt" \
  --register-timeout 3600 \
  --sanitize \
  --auth-only
```
## Roadmap

- [ ] Notifications by ip
- [ ] Server commands
- [x] WRAC protocol
- [x] RACS protocol