'use strict';

const port = 4000;

const fs = require('fs');
const https = require('https');

function handleRequest(request, response) {
    try {
        console.log(request.socket.remoteAddress, request.socket.remotePort, request.method, request.url);
        var cert = request.socket.getPeerCertificate();
        response.writeHead(200, {
            'Content-Type': 'text/plain'
        });
        response.write('You are identified as ');
        response.write(JSON.stringify(cert.subject));
        response.write('.\n\nFull certificate:\n');
        response.write(JSON.stringify(cert, null, 4));
        response.end();
    } catch (e) {
        response.writeHead(500, {
            'Content-Type': 'text/plain'
        });
        response.write('500 Internal Server Error');
        response.end();
    }
}

const server = https.createServer({
    key: fs.readFileSync('certs/web.key'),
    cert: fs.readFileSync('certs/web.crt'),
    ca: fs.readFileSync('certs/client.crt'),
    requestCert: true,
    rejectUnauthorized: true,
}, handleRequest);

server.on('connection', socket => {
    console.log(`Check: connection from [${socket.remoteAddress}]:${socket.remotePort}`);
});

server.on('clientError', (exception, socket) => {
    console.log(`Check: client error ${exception} on [${socket.remoteAddress}]:socket.remotePort`);
});

server.on('listening', () => {
    let address = server.address();
    console.log(`Check: listening on [${address.address}]:${address.port}`);
});

server.listen(port);
