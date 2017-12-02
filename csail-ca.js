'use strict';

const port = 3000;

const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const https = require('https');
const querystring = require('querystring');
const url = require('url');

const asn1 = forge.asn1;
const oids = forge.oids;
const pki = forge.pki;
const certificate = new crypto.Certificate();

function maxExpires() {
    let tmp = new Date();
    tmp.setTime(tmp.getTime() + 220 * 24 * 60 * 60 * 1000);
    return new Date(Date.UTC(tmp.getUTCFullYear(), 6, 1, 4));
}

const users = new Map([
    ['foo', {
        fullname: 'Foo Bar',
        password: 'bar',
        mitid: '999999999',
    }],
]);

function htmlResponse(response, html) {
    response.writeHead(200, {
        'Content-Type': 'text/html',
    });
    response.write(html);
    response.end();
}

function errorResponse(response, code, msg) {
    response.writeHead(code, {
        'Content-Type': 'text/plain',
    });
    response.write(msg);
    response.end();
}

async function generateCert(args) {
    const cert = pki.createCertificate();
    cert.publicKey = pki.publicKeyFromPem(forge.util.binary.raw.encode(args.publicKey));

    const serial = await new Promise((resolve, reject) =>
        crypto.randomBytes(16, (err, buf) =>
            err ? reject(err) : resolve(buf)));
    serial[0] &= ~128;  // Force positive serial number
    cert.serialNumber = forge.util.binary.hex.encode(serial);

    const clientCaCert = pki.certificateFromPem(fs.readFileSync('certs/client-chained.crt'));
    const clientCaKey = pki.privateKeyFromPem(fs.readFileSync('certs/client-chained.key'));

    cert.setIssuer(clientCaCert.subject.attributes);
    cert.setSubject([...clientCaCert.subject.attributes, {
        name: 'commonName',
        value: args.user.fullname,
    }, {
        name: 'emailAddress',
        value: `${args.login}@testca.test`,
    }]);
    cert.validity.notBefore = args.notBefore;
    cert.validity.notAfter = args.notAfter;

    cert.setExtensions([{
        name: 'keyUsage',
        critical: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
    }, {
        name: 'extKeyUsage',
        clientAuth: true,
        emailProtection: true,
        timeStamping: true,
    }, {
        name: 'nsCertType',
        client: true,
        email: true,
    }, {
        name: 'basicConstraints',
        cA: false
    }, {
        name: 'certificatePolicies',
        value: asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(
                    asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer('1.2.840.113554.3.1.2.2').getBytes()),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                        asn1.create(
                            asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                            asn1.oidToDer('1.3.6.1.5.5.7.2.1').getBytes()),
                        asn1.create(
                            asn1.Class.UNIVERSAL, asn1.Type.IA5STRING, false,
                            'http://testca.test/cps.txt'),
                    ]),
                ]),
            ]),
        ]),
    }, {
        name: 'cRLDistributionPoints',
        altNames: [{
            type: 6,
            value: 'http://testca.test/testclient.crl',
        }],
    }, {
        name: 'authorityInfoAccess',
        value: asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(
                    asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer('1.3.6.1.5.5.7.48.2').getBytes()),
                asn1.create(
                    asn1.Class.CONTEXT_SPECIFIC, 6, false,
                    'http://testca.test/'),
            ]),
        ]),
    }, {
        name: 'subjectKeyIdentifier',
    }, {
        name: 'authorityKeyIdentifier',
        keyIdentifier: true,
    }, {
        id: oids.subjectAltName,
        value: asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(
                asn1.Class.CONTEXT_SPECIFIC, 4, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                    asn1.oidToDer('0.9.2342.19200300.100.1.25').getBytes()),
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.IA5STRING, false,
                                    'test'),
                            ]),
                        ]),
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                    asn1.oidToDer('0.9.2342.19200300.100.1.25').getBytes()),
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.IA5STRING, false,
                                    'testca'),
                            ]),
                        ]),
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                    asn1.oidToDer(oids.organizationalUnitName).getBytes()),
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.UTF8, false,
                                    'Users'),
                            ]),
                        ]),
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                    asn1.oidToDer('0.9.2342.19200300.100.1.1').getBytes()),
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.UTF8, false,
                                    args.login),
                            ]),
                        ]),
                    ])
                ]),
            asn1.create(
                asn1.Class.CONTEXT_SPECIFIC, 1, false,
                `${args.login}@testca.test`),
        ]),
    }, {
        id: '1.2.840.113554.3.1.1.2',
        value: asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.IA5STRING, false,
            `${args.login}@testca.test`),
    }]);

    cert.sign(clientCaKey, forge.md.sha256.create());

    const p7 = forge.pkcs7.createSignedData();
    p7.content = '';
    p7.addCertificate(cert);
    p7.addCertificate(clientCaCert);
    p7.addCertificate(pki.certificateFromPem(fs.readFileSync('certs/root.crt')));
    return asn1.toDer(p7.toAsn1()).getBytes();
}

function authenticate(request) {
    const auth = request.headers.authorization;
    if (!auth || !auth.startsWith('Basic '))
        return null;
    const [_, login, password] = forge.util.decode64(auth.slice('Basic '.length)).match(/^([^:]*):(.*)$/);
    const user = users.get(login);
    return user && password === user.password ? login : null;
}

async function handleAuthRequest(login, request, response) {
    const u = url.parse(request.url);
    if (u.pathname === '/') {
        return htmlResponse(response, `\
<!DOCTYPE html>
<html>
  <head>
    <title>Test Certificate Authority</title>
  </head>
  <body>
    <ul>
      <li><a href="https://${request.headers.host}/request?ca=client;type=spkac">Request a Test CA client certificate</a></li>
      <li><a href="/cacert">Download Certificate Authority certificates</a></li>
    </ul>
  </body>
</html>
`);
    } else if (u.pathname === '/cacert' || u.pathname === '/cacert/') {
        return htmlResponse(response, `\
<!DOCTYPE html>
<html>
  <head>
    <title>Test CA: Download Certificate Authority Certificates</title>
  </head>
  <body>
    <table>
      <tbody>
      <tr>
      <td><a href="/cacert/master.pem">Test Master CA</a></td>
      <td>PEM (ASCII-armored, for OpenSSL)</td>
      </tr>
      <tr>
      <td><a href="/cacert/master.cer">Test Master CA</a></td>
      <td>DER (binary, for Windows and all browsers)</td>
      </tr>
      <tr>
      <td><a href="/cacert/client.pem">Test Client CA</a></td>
      <td>PEM (ASCII-armored, for OpenSSL)</td>
      </tr>
      <tr>
      <td><a href="/cacert/client.cer">Test Client CA</a></td>
      <td>DER (binary, for Windows and all browsers)</td>
      </tr>
      </tbody>
    </table>
  </body>
</html>
`);
    } else if (u.pathname === '/cacert/master.pem') {
        response.writeHead(200, {
            'Content-Type': 'text/plain',
        });
        response.write(fs.readFileSync('certs/root.crt'));
        response.end();
    } else if (u.pathname === '/cacert/master.cer') {
        response.writeHead(200, {
            'Content-Type': 'application/x-x509-ca-cert',
        });
        response.write(new Buffer(asn1.toDer(pki.certificateToAsn1(pki.certificateFromPem(fs.readFileSync('certs/root.crt')))).getBytes(), 'binary'));
        response.end();
    } else if (u.pathname === '/cacert/client.pem') {
        response.writeHead(200, {
            'Content-Type': 'text/plain',
        });
        response.write(fs.readFileSync('certs/client-chained.crt'));
        response.end();
    } else if (u.pathname === '/cacert/client.cer') {
        response.writeHead(200, {
            'Content-Type': 'application/x-x509-ca-cert',
        });
        response.write(new Buffer(asn1.toDer(pki.certificateToAsn1(pki.certificateFromPem(fs.readFileSync('certs/client-chained.crt')))).getBytes(), 'binary'));
        response.end();
    } else if (u.pathname === '/request' || u.pathname.startsWith('/request/')) {
        let data;
        if (request.method === 'POST') {
            data = '';
            request.on('data', chunk => data += chunk);
            await new Promise((resolve, reject) => request.on('end', resolve));
        } else {
            data = (u.query || '').replace(';', '&');
        }
        const query = querystring.parse(data);
        if (!query.ca || !query.type) {
            return htmlResponse(response, `\
<!DOCTYPE html>
<html>
  <head>
    <title>Test CA: Select type of certificate request</title>
  </head>
  <body>
    <table>
      <tbody>
      <tr>
      <td><a href="/request?ca=client;type=pkcs10">Test Client CA</a></td>
      <td>PKCS#10 Certificate Signing Request</td>
      </tr>
      <tr>
      <td><a href="/request?ca=client;type=spkac">Test Client CA</a></td>
      <td>Netscape signedPublicKeyAndChallenge</td>
      </tr>
      </tbody>
    </table>
  </body>
</html>
`);
        } else if (request.method === 'POST' && query.ca === 'client' && query.type === 'spkac' && certificate.verifySpkac(Buffer.from(query.spkac))) {
            // Do we care about the challenge?  Apparently not.
            const cert = await generateCert({
                login: login,
                user: users.get(login),
                notBefore: new Date(),
                notAfter: maxExpires(),
                publicKey: certificate.exportPublicKey(Buffer.from(query.spkac)),
            });
            response.writeHead(200, {
                'content-disposition': 'inline',
                'Content-Type': 'application/x-x509-user-cert',
            });
            response.write(new Buffer(cert, 'binary'));
            response.end();
        } else if (query.ca === 'client' && query.type === 'spkac') {
            const challengeBuf = await new Promise((resolve, reject) =>
                crypto.randomBytes(16, (err, buf) =>
                    err ? reject(err) : resolve(buf)));
            challengeBuf[0] |= 128;
            const challenge = new forge.jsbn.BigInteger([0, ...challengeBuf], 256);
            return htmlResponse(response, `\
<!DOCTYPE html>
<html>
  <head>
    <title>Test CA: Request a client certificate for your browser</title>
  </head>
  <body>
    <form method="post" value="/request"> <input type="hidden" name="ca" value="client"> <input type="hidden" name="type" value="spkac">
    <p><keygen name="spkac" keytype="rsa" challenge="${challenge}"></p>
    <input type="submit" name="Submit" value="Submit"> </form>
  </body>
</html>
`);
        } else {
            return errorResponse(response, 403, 'Invalid certificate request');
        }
    } else {
        return errorResponse(response, 404, '404 Not Found');
    }
}

async function handleRequest(request, response) {
    try {
        console.log(request.socket.remoteAddress, request.socket.remotePort, request.method, request.url);
        const login = authenticate(request);
        if (login) {
            return await handleAuthRequest(login, request, response);
        } else {
            response.writeHead(401, {
                'Content-Type': 'text/plain',
                'WWW-Authenticate': 'Basic realm="Test CA"',
            });
            response.write('401 Authorization Required');
            response.end();
        }
    } catch (e) {
        errorResponse(response, 500, '500 Internal Server Error');
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
    console.log(`client error ${exception} on [${socket.remoteAddress}]:${socket.remotePort}`);
});

server.on('listening', () => {
    let address = server.address();
    console.log(`listening on [${address.address}]:${address.port}`);
});

server.listen(port);
