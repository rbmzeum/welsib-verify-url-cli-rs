# build

```bash
RUSTFLAGS='-L staticlib' cargo build --release
```

# examples

```bash
echo "9e4c452444fb1de73afc6e3c057b6c3ae6f01c179a10248a283985d08636d7b0c9e28968fafc1323f35985267080631b64aa90363a745ef0549faa1ed87cf219ca4dbd8e97e95550ca4452c7aca427796752433050c68fab4b3c9ce236a03ae79f050e775f37eeedaf9a57fc721aa823540a6a77340e533957e47cc0354d51fa" | ./target/release/esig-verify-url https://welsib.ru

echo "9e4c452444fb1de73afc6e3c057b6c3ae6f01c179a10248a283985d08636d7b0c9e28968fafc1323f35985267080631b64aa90363a745ef0549faa1ed87cf219ca4dbd8e97e95550ca4452c7aca427796752433050c68fab4b3c9ce236a03ae79f050e775f37eeedaf9a57fc721aa823540a6a77340e533957e47cc0354d51fa" | ./target/release/esig-verify-url https://welsib.ru/doc.html

echo "9e4c452444fb1de73afc6e3c057b6c3ae6f01c179a10248a283985d08636d7b0c9e28968fafc1323f35985267080631b64aa90363a745ef0549faa1ed87cf219ca4dbd8e97e95550ca4452c7aca427796752433050c68fab4b3c9ce236a03ae79f050e775f37eeedaf9a57fc721aa823540a6a77340e533957e47cc0354d51fa" | ./target/release/esig-verify-url https://welsib.ru/license.txt
```