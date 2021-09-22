# SGX Verification Service

用于验证 SGX 服务器证书。


## Build and Run

```bash
# Compile wasm file
cd wasm
GOARCH=wasm GOOS=js go build -o main.wasm
cd ../verify_web
```

```bash
# Local development
yarn && yarn dev
```

