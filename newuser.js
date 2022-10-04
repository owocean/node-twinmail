const argon2 = require('argon2');

if (process.argv[2] == "confirm" && process.argv[3] && process.argv[4]) {
    newUser(process.argv[3], process.argv[4]);
}

async function newUser(username, password) {
    let hash = await argon2.hash(password);
    let s = JSON.parse(fs.readFileSync('store.json').toString('utf-8'));
    s['user.'+username+'.passwd'] = hash;
    fs.writeFileSync('store.json', JSON.stringify(s));
}

module.exports = newUser;