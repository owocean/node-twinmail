const tls = require('tls');
const URL = require('url').URL;
const fs = require('fs');
const crypto = require('crypto');
const argon2 = require('argon2');

let defaultaini = `# tls key and cert for tls connections
tlskey = key.pem
tlscert = cert.pem
# host and port to listen on
host = 0.0.0.0
port = 1965
# hostname accessible via internet (domain name)
hostname = localhost
# forward gemini requests to a separate gemini server
forwardrequests = false
forwardport = 1966
# server name and description
servername = My twinmail server
serverdesc = Gentlemen do not read each other's mail`;

if (!fs.existsSync('config.txt')) fs.writeFileSync('config.txt', defaultaini);
if (!fs.existsSync('store.json')) fs.writeFileSync('store.json', '{}');
if (!fs.existsSync('mail/')) fs.mkdirSync('mail/');

const files = {
    readConfig: function () {
        try {
            let s = fs.readFileSync('config.txt').toString('utf-8');
            return parse(s);
        } catch (err) {
            console.log("\nAn Error occured while parsing the config file. Please ensure that config.txt exists, and that it is formatted properly.\n");
        }
    },
    readDB: function () {
        let s = fs.readFileSync('store.json').toString('utf-8');
        return JSON.parse(s);
    },
    writeDB: function (s) {
        fs.writeFileSync('store.json', JSON.stringify(s));
    }
}

const config = files.readConfig();

const options = {
    key: fs.readFileSync(config.tlskey),
    cert: fs.readFileSync(config.tlscert),
    rejectUnauthorized: false,
    requestCert: true
};

const server = tls.createServer(options, function (socket) {
    let req = "";
    let gotHeader = false;
    let length = 0;
    let request;
    socket.on('data', function (data) {
        req += data.toString();
        if (req.includes('\r\n') && !gotHeader) {
            request = new URL(req.toString().split('\n')[0]);
            if (request.protocol == "twin:") {
                gotHeader = true;
                if (request.pathname == "/") {
                    badRequest(socket);
                } else {
                    length = parseInt(request.hash.slice(1));
                    if (isNaN(length)) {
                        badRequest(socket);
                    }
                }
            } else if (config.forwardrequests == "true") {
                let forward = tls.connect(config.forwardport, function () {
                    forward.write(req);
                });
                forward.on('data', function (d) {
                    socket.write(d);
                });
                forward.on('end', function () {
                    socket.end();
                });
            } else {
                badRequest(socket);
            }
        }
        let body = req.split('\n').slice(1).join('\n');
        if (body.length >= length && !socket.closed) {
            if (request == undefined) return badRequest(socket);
            let apicall = request.pathname.split('/')[1].toUpperCase();
            switch (apicall) {
                case "KEYS":
                    getUserKeys(socket, body);
                    break;
                case "SETKEYS":
                    setUserKeys(socket, body);
                    break;
                case "POST":
                    post(socket, body);
                    break;
                case "INBOX":
                    inbox(socket, body);
                    break;
                case "TOKEN":
                    getToken(socket, body);
                    break;
                case "OUTBOX":
                    getOutbox(socket, body);
                    break;
                case "GET":
                    getMail(socket, body);
                    break;
                case "DELETE":
                    deleteMail(socket, body);
                    break;
                case "LOGOUT":
                    deleteToken(socket, body);
                    break;
                case "INFO":
                    getInfo(socket);
                    break;
                case "NEW":
                    checkServer(socket, body);
                    break;
                default:
                    badRequest(socket);
                    break;
            }
        }
        socket.on('error', function () {
            req = null;
        });
    });
});

function badRequest(sock) {
    sock.write('59 Bad Request\r\n');
    sock.end();
}

function getUserKeys(sock, msg) {
    if (msg == "") return badRequest(sock);
    let db = files.readDB();
    let key = db['user.' + msg];
    if (key == undefined) {
        sock.write('51 No key found\r\n');
        sock.end();
        return;
    }
    sock.write('20 text/plain\r\nkey=' + key + '\r\n');
    sock.end();
}

function setUserKeys(sock, msg) {
    if (msg == "") return badRequest(sock);
    let db = files.readDB();
    let req = parse(msg);
    if (!req.token || !req.key) return badRequest(sock);
    if (db['tokens.' + req.token]) {
        let user = db['tokens.' + req.token];
        db['user.' + user] = req.key;
        files.writeDB(db);
        sock.write('20 text/plain\r\n\r\n');
        sock.end();
    } else {
        sock.write('61 Unauthorized\r\n');
        sock.end();
    }
}

function post(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.token || !req.body || !req.server) return badRequest(sock);
    let db = files.readDB();
    let destination = 'outbox.' + req.server;
    if (req.server == config.hostname) {
        let headers = parse(req.body);
        if (!headers.recipient) return;
        let username = headers.recipient.split('@')[0].split('+')[0]
        destination = 'inbox.' + username;
    }
    if (db['tokens.' + req.token]) {
        let id = crypto.randomBytes(8).toString('hex');
        fs.writeFileSync('mail/' + id, stringify(req.body, 2));
        if (!db[destination]) db[destination] = [];
        db[destination].push(id);
        files.writeDB(db);
        sock.write('20 text/plain\r\n\r\n');
        sock.end();
        
    } else {
        sock.write('61 Unauthorized\r\n');
        sock.end();
    }
}

function inbox(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.token) return badRequest(sock);
    let db = files.readDB();
    if (db['tokens.' + req.token]) {
        let user = db['tokens.' + req.token];
        if (!db['inbox.' + user]) db['inbox.' + user] = [];
        sock.write('20 text/plain\r\n' + stringify(db['inbox.' + user]) + '\r\n');
        sock.end();
    } else {
        sock.write('61 Unauthorized\r\n');
        sock.end();
    }
}

async function getToken(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.username || !req.password) return badRequest(sock);
    let db = files.readDB();
    if (!db['user.' + req.username + '.passwd']) {
        sock.write('51 no such user found');
        return sock.end();
    }
    if (await argon2.verify(db['user.' + req.username + '.passwd'], req.password)) {
        let token = crypto.randomBytes(16).toString('hex');
        db['tokens.' + token] = req.username;
        files.writeDB(db);
        sock.write('20 text/plain\r\ntoken=' + token + '\r\n');
        sock.end();
    } else {
        sock.write('61 Unauthorized\r\n');
        sock.end();
    }
}

function getOutbox(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.host) return badRequest(sock);
    let db = files.readDB();
    if (!db['outbox.' + req.host]) db['outbox.' + req.host] = [];
    sock.write('20 text/plain\r\n' + stringify(db['outbox.' + req.host], 2) + '\r\n');
    sock.end();
}

function getMail(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.id) return badRequest(sock);
    try {
        let mail = fs.readFileSync('mail/' + req.id.replace(/\//g, ""));
        sock.write('20 text/plain\r\n' + mail + '\r\n');
        sock.end();
    } catch (err) {
        sock.write('51 Not found\r\n');
        sock.end();
    }
}

function deleteMail(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.id || !req.token) return badRequest(sock);
    if (db['tokens.' + req.token]) {
        let user = db['tokens.' + req.token];
        let inbox = db['inbox.' + user];
        if (!inbox) db['inbox.' + user] = [];
        if (inbox.includes(req.id)) {
            db['inbox.' + user].splice(inbox.indexOf(req.id), 1);
            files.writeDB(db);
            try {
                fs.rmSync('mail/' + req.id.replace(/\//g, ""));
                sock.write('20 text/plain\r\n\r\n');
                sock.end();
            } catch (err) {
                sock.write('51 Not found\r\n');
                sock.end();
            }
        } else {
            sock.write('51 Not found\r\n');
            sock.end();
        }
    } else {
        sock.write('61 Unauthorized\r\n');
        sock.end();
    }
}

async function deleteToken(sock, msg) {
    if (msg == "") return badRequest(sock);
    let req = parse(msg);
    if (!req.token) return badRequest(sock);
    let db = files.readDB();
    if (db['tokens.' + req.token]) {
        delete db['tokens.' + req.token];
    }
    sock.write('20 text/plain\r\n\r\n');
    sock.end();
}

function getInfo(sock) {
    let name = config.servername || "no name";
    let desc = config.serverdesc || "no description";
    sock.write('20 text/plain\r\n' + stringify({ name, desc }, 2) + '\r\n');
    sock.end();
}

server.listen(config.port, config.host, function () {
    console.log("Started listening on %s, port %s", config.host, config.port);
});

function checkServer(socket,msg) {
    socket.write("20 text/plain\r\n\r\n");
    socket.end();
    let req = parse(msg);
    if (!req.host) return badRequest(sock);
    if (req.host == config.hostname) return;
    let sock = tls.connect({
        host: req.host, port: 1965, rejectUnauthorized: false
    }, function () {
        let body = "host=" + config.hostname + "\r\n";
        sock.write('twin://' + req.host + '/outbox#' + body.length + "\r\n" + body);
    });
    sock.on('data', function (data) {
        if (data.startsWith('20 text/plain')) {
            let mail = parse(data.split('\r\n')[1]);
            fetchmail(mail, req.host);
        }
    });
}

function fetchmail(mail, host) {
    for (let msg of mail) {
        if (!fs.existsSync('mail/' + msg.replace(/\//g, ""))) {
            let sock = tls.connect({
                host, port: 1965, rejectUnauthorized: false
            }, function () {
                let body = "id=" + msg + "\r\n";
                sock.write('twin://' + host + '/get#' + body.length + "\r\n" + body);
            });
            sock.on('data', function (data) {
                if (data.startsWith('20 text/plain')) {
                    let body = data.split('\r\n').slice(1).join('\r\n');
                    let headers = parse(body);
                    if (!headers.recipient) return;
                    let username = headers.recipient.split('@')[0].split('+')[0]
                    let db = files.readDB();
                    if (!db['inbox.' + username]) db['inbox.' + username] = [];
                    db['inbox.' + username].push(msg);
                    files.writeDB(db);
                    fs.writeFileSync('mail/' + msg.replace(/\//g, ""), body);
                }
            });
        }
    }
}

function parse(str) {
    let obj = {};
    let k = null;
    for (let line of str.split('\n')) {
        let section = line.match(/^\[(.+)\]$/);
        if (section != null) {
            k = section[1];
        } else {
            let declaration = line.trim().match(/^(.+)=(.+)$/);
            if (declaration != null) {
                if (k == null) {
                    obj[declaration[1].trim()] = declaration[2].trim();
                } else {
                    obj[k][declaration[1].trim()] = declaration[2].trim();
                }
            }
        }
    }
    return obj;
}

function stringify(obj) {
    let first = "";
    let second = "";
    for (let key of Object.keys(obj)) {
        if (typeof obj[key] == 'object') {
            second += "\n[" + key + "]";
            for (let key2 of Object.keys(obj[key])) {
                second += "\n"+key2+"=" + obj[key2];
            }
        } else {
            first += "\n"+key+"=" + obj[key];
        }
    }
    return first.trim() + second;
}