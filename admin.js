const argon2 = require('argon2');
const fs = require('fs');

const arg = process.argv;

if (arg[2] == "newuser" && arg[3] && arg[4]) {
    newUser(arg[3], arg[4]);
} else if (arg[2] == "deluser" && arg[3]) {
    delUser(arg[3]);
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
