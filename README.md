# arqma-storage-server
Storage server for Arqma Service Nodes

Requirements:
all required dependencies sources are downloaded and platform specific build mode is included to main build process.
as well as submodules update.

Building from git clone:
```
git clone https://github.com/arqma/arqma-storage-server.git
cd arqma-storage-server
make all
```

Compiled program will be build inside
```
binaries
```
folder :)

To run the storage-server:
```
./arqma-storage <public IP> <port> --arqmad-rpc-port <port at which arqmad is listening>
```
Replace the 0.0.0.0 with your IP of the hardware running the Storage-Server
Ensure your ports are open to allow communication to other network Storage-servers
The paths for Boost and OpenSSL can be specified by exporting the variables in the terminal before running make:

```
export OPENSSL_ROOT_DIR = ...
export BOOST_ROOT= ...
```

To get command line options just run:
```
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
