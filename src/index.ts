import express, { Request, Response } from 'express';
import axios from 'axios';
import * as lodash from 'lodash';
import minimist from 'minimist';
import serialize from 'serialize-javascript';
import * as handlebars from 'handlebars';
import UAParser from 'ua-parser-js';
import * as forge from 'node-forge';
import moment from 'moment';

const app = express();
const port = 3000;

app.use(express.json());

// Vulnerable endpoint using lodash (Prototype Pollution)
app.post('/api/merge', (req: Request, res: Response) => {
  const defaultConfig = {};
  const userConfig = req.body;

  // Vulnerable to prototype pollution
  const merged = lodash.merge(defaultConfig, userConfig);

  res.json({ message: 'Config merged', config: merged });
});

// Vulnerable endpoint using axios (SSRF)
app.get('/api/fetch', async (req: Request, res: Response) => {
  const url = req.query.url as string;

  try {
    // Vulnerable to SSRF attacks
    const response = await axios.get(url);
    res.json({ data: response.data });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Vulnerable endpoint using minimist (Prototype Pollution)
app.get('/api/parse-args', (req: Request, res: Response) => {
  const args = req.query.args ? (req.query.args as string).split(' ') : [];

  // Vulnerable to prototype pollution
  const parsed = minimist(args);

  res.json({ parsed });
});

// Vulnerable endpoint using handlebars (RCE)
app.post('/api/template', (req: Request, res: Response) => {
  const templateString = req.body.template;
  const data = req.body.data;

  // Vulnerable to RCE through template injection
  const template = handlebars.compile(templateString);
  const result = template(data);

  res.send(result);
});

// Vulnerable endpoint using serialize-javascript (XSS)
app.get('/api/serialize', (req: Request, res: Response) => {
  const data = req.query.data;

  // Vulnerable to XSS
  const serialized = serialize(data);

  res.send(`<html><body><script>var data = ${serialized};</script></body></html>`);
});

// Endpoint using ua-parser-js (ReDoS)
app.get('/api/parse-ua', (req: Request, res: Response) => {
  const userAgent = req.headers['user-agent'];

  // Vulnerable to ReDoS
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  res.json(result);
});

// Endpoint using moment (ReDoS)
app.get('/api/format-date', (req: Request, res: Response) => {
  const date = req.query.date as string;
  const format = (req.query.format as string) || 'YYYY-MM-DD';

  // Vulnerable to ReDoS through malicious format strings
  const formatted = moment(date).format(format);

  res.json({ formatted });
});

// Endpoint using node-forge
app.post('/api/encrypt', (req: Request, res: Response) => {
  const text = req.body.text;
  const key = req.body.key || 'default-key';

  // Using vulnerable version of node-forge
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.update(forge.util.createBuffer(text));
  cipher.finish();

  const encrypted = cipher.output.toHex();

  res.json({ encrypted });
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'running',
    timestamp: new Date().toISOString(),
    vulnerabilities: 'intentional - for security scanning demo'
  });
});

app.listen(port, () => {
  console.log(`Vulnerable demo app listening at http://localhost:${port}`);
  console.log('WARNING: This application contains intentional vulnerabilities for security scanning demonstration !');
  console.log('DO NOT deploy this application in production');
});

export default app;
