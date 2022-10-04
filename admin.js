const argon2 = require('argon2');
const tls = require('tls');
const CKT = require("cktjs");
const fs = require('fs');

const arg = process.argv;

if (arg[2] == "newuser" && arg[3] && arg[4]) {
    newUser(arg[3], arg[4]);
} else if (arg[2] == "deluser" && arg[3]) {
    delUser(arg[3]);
} else if (arg[2] == "sub" && arg[3]) {
    subscribe(arg[3]);
} else if (arg[2] == "unsub" && arg[3]) {
    unsubscribe(arg[3]);
} else if (arg[2] == "callme" && arg[3]) {
    callMe(arg[3], false);
} else if (arg[2] == "deleteme" && arg[3]) {
    callMe(arg[3], true);
}

async function newUser(username, password) {
    let hash = await argon2.hash(password);
    let s = JSON.parse(fs.readFileSync('store.json').toString('utf-8'));
    s['user.' + username + '.passwd'] = hash;
    fs.writeFileSync('store.json', JSON.stringify(s));
    console.log('created user');
}

function delUser(username) {
    let s = JSON.parse(fs.readFileSync('store.json').toString('utf-8'));
    delete s['user.' + username + '.passwd'];
    delete s['user.' + username + '.enc'];
    delete s['user.' + username + '.sign'];
    delete s['inbox.' + username];
    fs.writeFileSync('store.json', JSON.stringify(s));
    console.log('deleted user');
}

function subscribe(host) {
    let s = JSON.parse(fs.readFileSync('store.json').toString('utf-8'));
    if (!s.ring) s.ring = [];
    s.ring.push(host);
    fs.writeFileSync('store.json', JSON.stringify(s));
    console.log('subscribed to server');
}

function unsubscribe(host) {
    let s = JSON.parse(fs.readFileSync('store.json').toString('utf-8'));
    if (!s.ring) s.ring = [];
    if (s.ring.includes(host)) {
        s.ring.splice(s.ring.indexOf(host), 1);
    }
    fs.writeFileSync('store.json', JSON.stringify(s));
    console.log('unsubscribed from server');
}

function callMe(host, deleteMe) {
    let sock = tls.connect({
        host, port: 1965, rejectUnauthorized: false
    }, function () {
        let s = CKT.parse(fs.readFileSync('config.txt').toString('utf-8'));
        let body = "hostname=" + s.hostname + "\nport=" + s.port + "\r\n";
        sock.write('twin://' + host + '/' + (deleteMe ? 'delete' : 'call') + 'me#' + body.length + "\r\n" + body);
    });
    sock.on('data', function (data) {
        if (data.startsWith('20 ')) {
            console.log('server has received request');
        }
    });
}