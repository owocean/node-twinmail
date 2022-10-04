# node-twinmail
A small node.js server for the twinmail protocol

## usage
clone it!
```sh
$ git clone https://github.com/owocean/node-twinmail.git
```
install it!
```sh
$ npm i
```
generate certificates! (for ssl/tls)
```sh
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -nodes -days 365
```
run it!
```sh
$ npm start
```
upon running for the first time, `store.json`, `config.txt`, and `mail/` will be created automatically in the active directory. edit `config.txt` accordingly!

## moderating the server
since there are some things that can't be handled automatically like account creation or unsubscribing from other servers, a CLI script named `admin.js` was included. this script can be spawned by other processes if desired.
```sh
# creating a new user
$ node admin newuser username password

# delete a user
$ node admin deluser username

# subscribe to a server (this happens automatically)
$ node admin sub hostname

# unsubscribe from a server
$ node admin unsub hostname

# ask a server to subscribe to you (this happens automatically)
$ node admin callme hostname

# ask a server to unsubscribe from you
$ node admin deleteme hostname
```
