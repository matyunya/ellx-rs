import commandLineArgs from 'command-line-args';
import { resolve } from 'path';
import cors from 'cors';
import polka from 'polka';
import { Request, Response, NextFunction, RequestHandler } from 'express';
import fetch from 'node-fetch';
import { json } from 'body-parser';
import * as ec from './util/ec';
import WebSocket from 'ws';
import { createServer } from 'http';
import serveFiles from './util/serve_files';

type FSHeaders = Headers & {
  authorization?: string;
}

type StatusCode = number;

export type FSRequest = Request & {
  headers: FSHeaders;
}

export type FSResponse = Response & {
  statusCode: StatusCode;

  sendJson: (resp: any) => void;
  error: (error: any, status: StatusCode) => void;
}

const optionDefinitions = [
  { name: 'user', alias: 'u', type: String, defaultOption: true },
  { name: 'trust', alias: 't', type: String },
  { name: 'identity', alias: 'i', type: String },
  { name: 'port', alias: 'p', type: Number },
  { name: 'root', alias: 'r', type: String }
];

const config = commandLineArgs(optionDefinitions);

config.port = config.port || 3002;
config.trust = config.trust || 'https://api.ellx.io/certificate';
config.identity = config.identity || 'localhost~' + config.port;
config.root = resolve(process.cwd(), config.root || '.');

// TODO: RegEx check and warn for user and identity

if (!config.user) {
  console.log('Please provide your user name using -u <username> option');
  process.exit();
}

const helpers = (_: FSRequest, res: FSResponse, next: NextFunction) => {
  res.sendJson = (resp: any) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(resp));
  }
  res.error = (error: any, status: StatusCode = 500) => {
    res.statusCode = status;
    res.sendJson({
      error
      // TODO: context
    });
  };
  next();
}

const server = createServer();

fetch(config.trust).then(r => {
  if (r.ok) return r.text();

  throw new Error(`${r.status} ${r.statusText}`);
}).then(cert => {
  console.log(`Successfully fetched ${config.trust}: ${cert}`);
  const publicKey = ec.keyFromPublic(cert);

  const auth = (handler: RequestHandler) => (req: FSRequest, res: FSResponse, next: NextFunction) => {
    if (!req.headers.authorization) {
      return res.error('No authorization header', 401);
    }

    const [ts, signature] = req.headers.authorization.split(',');
    const payload = [config.user, config.identity, ts].join(',');

    if (!publicKey.verify(payload, signature)) {
      res.error('Forbidden', 403);
    }
    else return handler(req, res, next);
  }

  const app = polka({ server });

  app
    .use(json(), helpers, cors())
    .use('/resource', auth(serveFiles(config.root)))
    .get('/identity', (_: FSRequest, res: FSResponse) => res.end(config.identity))

  app.listen(config.port, (err: Error) => {
      if (err) throw err;
      console.log(`> Running on localhost:${config.port}`);
      console.log('Serving ' + config.root);
    });
});

const ws = new WebSocket.Server({ server, path: '/ws' });
