# arqma-storage-server
Storage server for Arqma Service Nodes

```
USE_SINGLE_BUILDDIR=1 make all
cd build/release/binaries

To get command line options just run:
./arqma-storage --help
```

Then using something like Postman (https://www.getpostman.com/) you can hit the API:

# post data
```
HTTP POST http://127.0.0.1/store
body: "hello world"
headers:
- X-Arqma-recipient: "mypubkey"
- X-Arqma-ttl: "86400"
- X-Arqma-timestamp: "1540860811000"
- X-Arqma-pow-nonce: "xxxx..."
```
# get data
```
HTTP GET http://127.0.0.1/retrieve
headers:
- X-Arqma-recipient: "mypubkey"
- X-Arqma-last-hash: "" (optional)
```