'use strict';

const port = 3000;

const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const https = require('https');
const querystring = require('querystring');
const xmlEscape = require('xml-escape');

function xml(pieces) {
    return pieces.map((piece, i) => i ? xmlEscape(arguments[i].toString()) + piece : piece).join('');
}

function showXml(response, xml) {
    response.writeHead(200, {
        'Content-Type': 'text/xml'
    });
    response.write(xml);
    response.end();
}

function showError(response, code, text) {
    return showXml(response, xml `\
<error>
  <code>${code}</code>
  <text>${text}</text>
</error>
`);
}

function maxExpires() {
    let tmp = new Date();
    tmp.setTime(tmp.getTime() + 190 * 24 * 60 * 60 * 1000);
    return new Date(Date.UTC(tmp.getUTCFullYear(), 7, 1, 12));
}

const users = new Map([
    ['foo', {
        fullname: 'Foo Bar',
        password: 'bar',
        mitid: '999999999',
    }],
]);

function validLogin(login) {
    return login == 'foo';
}

function validPassword(login, password) {
    return password == 'bar';
}

function validMitId(login, mitid) {
    return mitid == '999999999';
}

async function generateCert(args) {
    const cert = forge.pki.createCertificate();

    const keyPair = await new Promise((resolve, reject) =>
        forge.pki.rsa.generateKeyPair({bits: 2048}, (err, keyPair) =>
            err ? reject(err) : resolve(keyPair)));
    cert.publicKey = keyPair.publicKey;

    const serial = await new Promise((resolve, reject) =>
        crypto.randomBytes(16, (err, buf) =>
            err ? reject(err) : resolve(buf)));
    serial[0] &= ~128;  // Force positive serial number
    cert.serialNumber = forge.util.binary.hex.encode(serial);

    const clientCaCert = forge.pki.certificateFromPem(fs.readFileSync('certs/client.crt'));
    const clientCaKey = forge.pki.privateKeyFromPem(fs.readFileSync('certs/client.key'));

    cert.setIssuer(clientCaCert.subject.attributes);
    cert.setSubject([...clientCaCert.subject.attributes, {
        name: 'commonName',
        value: `${args.user.fullname}/emailAddress=${args.login}@testca.test`,
    }]);
    cert.validity.notBefore = args.notBefore;
    cert.validity.notAfter = args.notAfter;

    cert.setExtensions([{
        name: 'basicConstraints',
        cA: false
    }, {
        name: 'nsCertType',
        client: true,
        email: true,
    }, {
        name: 'extKeyUsage',
        emailProtection: true,
        clientAuth: true,
    }, {
        name: 'keyUsage',
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
    }, {
        name: 'subjectKeyIdentifier',
    }, {
        name: 'cRLDistributionPoints',
        altNames: [{
            type: 6,
            value: 'http://testca.test/testclient.crl',
        }],
    }]);

    cert.sign(clientCaKey, forge.md.sha256.create());

    const p12 = forge.pkcs12.toPkcs12Asn1(keyPair.privateKey, cert, args.downloadpassword, {
        algorithm: '3des',
        friendlyName: `${args.user.fullname}'s Test Certificate`,
    });
    return forge.asn1.toDer(p12).getBytes();
}

const sessions = new Map();

const operations = {
    startup: async (cmd, response) => {
        if (cmd.sessiontype != 'xml')
            return showError(response, 3, 'Invalid sessiontype: Only "xml" is supported');
        if (cmd.version != '2')
            return showError(response, 2, 'Invalid Version: Must be 2'); // what are 1 and 3?
        if (!cmd.os || !cmd.browser)
            return showError(response, 4, 'Must provide browser and os information');

        const buf = await new Promise((resolve, reject) =>
            crypto.randomBytes(16, (err, buf) =>
                err ? reject(err) : resolve(buf)));
        const id = buf.toString('hex');
        const expires = new Date();
        expires.setTime(expires.getTime() + 21 * 60 * 60 * 1000);

        sessions[id] = {
            'id': id,
            'expires': expires,
        };
        return showXml(response, xml `\
<startupresponse>
   <sessiontype>xml</sessiontype>
   <sessionid>${id}</sessionid>
   <sessionexpires>${expires.toISOString().slice(0, -1) + '000'}</sessionexpires>
   <maxexpire>${maxExpires().toISOString().slice(0, -5)}</maxexpire>
</startupresponse>
`);
    },

    authenticate: (cmd, response) => {
        if (!cmd.sessionid || !cmd.login || !cmd.mitid || !cmd.password)
            return showError(response, 5, 'Required Parameter Missing');
        if (!(cmd.sessionid in sessions))
            return showError(response, 6, 'Invalid Session');
        const user = users.get(cmd.login);
        if (!user)
            return showError(response, 8, 'Principal does not exist');
        if (cmd.password !== user.password)
            return showError(response, 7, 'Invalid Password');
        if (cmd.mitid !== user.mitid)
            return showError(response, 9, 'Incorrect MIT ID Provided');
        sessions[cmd.sessionid].login = cmd.login;
        return showXml(response, xml `\
<authenticateresponse />
`);
    },

    downloadcert: async (cmd, response) => {
        if (!(cmd.sessionid in sessions))
            return showError(response, 6, 'Invalid Session');
        const login = sessions[cmd.sessionid].login;
        if (!login)
            return showError(response, 10, 'Not Logged In');
        if (!cmd.downloadpassword)
            return showError(response, 11, 'No Download Password Provided');
        if (!cmd.expiration)
            return showError(response, 12, 'No Expiration Date Provided');
        if (cmd.force != '0' && cmd.force != '1')
            return showError(response, 13, 'Force Parameter should be 0 or 1 (but is ignored)');
        if (cmd.alwaysreuse != '0' && cmd.alwaysreuse != '1')
            return showError(response, 13, 'alwaysreuse Parameter should be 0 or 1 (but is ignored)');
        const expiration = Date.parse(cmd.expiration);
        if (expiration != expiration)
            return showError(response, 12, 'Invalid Expiration Date Provided');
        const now = Date.now();
        const notBefore = new Date();
        notBefore.setTime(now - 24 * 60 * 60 * 1000);
        const notAfter = new Date();
        notAfter.setTime(Math.min(Math.max(expiration, now + 60 * 60 * 1000), maxExpires()));
        const pkcs12 = await generateCert({
            login: login,
            user: users.get(login),
            notBefore: notBefore,
            notAfter: notAfter,
            downloadpassword: cmd.downloadpassword
        });
        return showXml(response, xml `\
<downloadcertresponse>
<pkcs12>
${forge.util.encode64(pkcs12).match(/.{1,76}/g).join('\n')}

</pkcs12>
</downloadcertresponse>`); // no trailing newline
    },

    finish: (cmd, response) => {
        if (!(cmd.sessionid in sessions))
            return showError(response, 6, 'Invalid Session');
        sessions.delete(cmd.sessionid);
        return showXml(response, xml `\
<finishresponse />
`);
    },
};

function handleApi(request, response) {
    if (request.method != 'POST') {
        return showError(response, 1, 'Must use a form post');
    }
    let data = '';
    request.on('data', chunk => data += chunk);
    request.on('end', () => {
        const cmd = querystring.parse(data);
        if (!cmd.operation)
            return showError(response, 2, 'Must provide an operation');
        else if (cmd.operation in operations)
            return operations[cmd.operation](cmd, response);
        else
            return showError(response, 300, 'Function not yet implemented');
    });
}

async function handleRequest(request, response) {
    try {
        console.log(request.socket.remoteAddress, request.socket.remotePort, request.method, request.url);
        if (request.url.startsWith('/ca/api')) {
            return await handleApi(request, response);
        } else {
            response.writeHead(404, {
                'Content-Type': 'text/plain'
            });
            response.write('404 Not Found');
            response.end();
        }
    } catch (e) {
        response.writeHead(500, {
            'Content-Type': 'text/plain'
        });
        response.write('500 Internal Server Error');
        response.end();
        throw e;
    }
}

const server = https.createServer({
    key: fs.readFileSync('certs/web.key'),
    cert: fs.readFileSync('certs/web.crt'),
}, handleRequest);

server.on('connection', socket => {
    console.log(`connection from [${socket.remoteAddress}]:${socket.remotePort}`);
});

server.on('clientError', (exception, socket) => {
    console.log(`client error ${exception} on [${socket.remoteAddress}]:socket.remotePort`);
});

server.on('listening', () => {
    let address = server.address();
    console.log(`listening on [${address.address}]:${address.port}`);
});

server.listen(port);
