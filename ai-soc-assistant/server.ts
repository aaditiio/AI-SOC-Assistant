/**
 * Full-stack Express server for AI SOC Assistant
 * Integrates Vite middleware and provides robust local /api/* REST endpoints
 * for Cloud, Endpoints, Automation, Email Security, Alerts, Incidents, and Health.
 */
import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import {
  INITIAL_ALERTS,
  INITIAL_INCIDENTS,
  INITIAL_ASSETS,
  INITIAL_VULNERABILITIES,
  INITIAL_THREAT_INTEL,
  INITIAL_ENDPOINTS,
  INITIAL_CLOUD_RESOURCES,
  INITIAL_EMAIL_THREATS,
  INITIAL_PLAYBOOKS,
  INITIAL_CASES
} from './src/server/socEngine';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT || 3000;

  app.use(express.json());

  // API Index / Documentation
  app.get('/api', (_req: Request, res: Response) => {
    res.json({
      title: 'AI SOC Assistant Backend REST API',
      version: '2.5.0',
      description: 'Comprehensive Enterprise Security Operations Center API (Express + Node.js)',
      endpoints: [
        { path: '/api/health', method: 'GET', description: 'System health & ML model status' },
        { path: '/api/docs', method: 'GET', description: 'API endpoint documentation directory' },
        { path: '/api/alerts', method: 'GET', description: 'Active security alerts & telemetry' },
        { path: '/api/incidents', method: 'GET', description: 'Correlated incident triage tickets' },
        { path: '/api/cloud', method: 'GET', description: 'Cloud security posture & IAM findings' },
        { path: '/api/endpoints', method: 'GET', description: 'EDR sensor inventory & process isolation status' },
        { path: '/api/email-security', method: 'GET', description: 'Email threat defense & phishing telemetry' },
        { path: '/api/automation', method: 'GET', description: 'SOAR automated playbooks & response triggers' },
        { path: '/api/threat-intel', method: 'GET', description: 'Global IOC feeds & threat actor intelligence' },
        { path: '/api/assets', method: 'GET', description: 'Critical asset inventory & risk scoring' },
        { path: '/api/vulnerabilities', method: 'GET', description: 'CVE vulnerability scan findings' },
        { path: '/api/cases', method: 'GET', description: 'SOC investigation case management' }
      ]
    });
  });

  app.get('/api/docs', (_req: Request, res: Response) => {
    res.redirect('/api');
  });

  // API Health
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      backend: 'AI Studio Full-Stack Engine (Express + Node.js)',
      modelStatus: 'trained',
      datasetSamples: 5000,
      timestamp: new Date().toISOString()
    });
  });

  // REST API Endpoints for SOC Modules
  app.get('/api/alerts', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_ALERTS.length, data: INITIAL_ALERTS });
  });

  app.get('/api/incidents', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_INCIDENTS.length, data: INITIAL_INCIDENTS });
  });

  app.get('/api/cloud', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_CLOUD_RESOURCES.length, data: INITIAL_CLOUD_RESOURCES });
  });

  app.get('/api/endpoints', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_ENDPOINTS.length, data: INITIAL_ENDPOINTS });
  });

  app.get('/api/email-security', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_EMAIL_THREATS.length, data: INITIAL_EMAIL_THREATS });
  });

  app.get('/api/automation', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_PLAYBOOKS.length, data: INITIAL_PLAYBOOKS });
  });

  app.get('/api/threat-intel', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_THREAT_INTEL.length, data: INITIAL_THREAT_INTEL });
  });

  app.get('/api/assets', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_ASSETS.length, data: INITIAL_ASSETS });
  });

  app.get('/api/vulnerabilities', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_VULNERABILITIES.length, data: INITIAL_VULNERABILITIES });
  });

  app.get('/api/cases', (_req: Request, res: Response) => {
    res.json({ count: INITIAL_CASES.length, data: INITIAL_CASES });
  });

  // Network Intelligence & Security Center Endpoints
  app.get('/api/network/intelligence', (_req: Request, res: Response) => {
    res.json({
      resilienceScore: 84.5,
      totalBandwidthMbps: 485.4,
      packetsPerSecond: 18450,
      totalActiveHosts: 116,
      subnetsCount: 5,
      postureStatus: 'Active Defense',
      protocolsMonitored: ['HTTPS', 'Kerberos', 'DNS', 'PostgreSQL', 'SMB', 'SSH', 'gRPC'],
      timestamp: new Date().toISOString()
    });
  });

  app.get('/api/connectors', (_req: Request, res: Response) => {
    res.json({
      count: 5,
      data: [
        { id: 'conn-syslog-01', name: 'Perimeter Firewall Syslog Stream', protocol: 'Syslog RFC 5424', status: 'Connected' },
        { id: 'conn-splunk-01', name: 'Enterprise SIEM Forwarder', protocol: 'Splunk HEC / REST', status: 'Connected' },
        { id: 'conn-zeek-01', name: 'Core Switch Network Sensor', protocol: 'Zeek / Bro IDS (JSON)', status: 'Connected' },
        { id: 'conn-suricata-01', name: 'DMZ Gateway EVE Telemetry', protocol: 'Suricata EVE-JSON', status: 'Connected' },
        { id: 'conn-aws-01', name: 'AWS CloudTrail & GuardDuty', protocol: 'AWS EventBridge CloudWatch', status: 'Connected' }
      ]
    });
  });

  app.post('/api/ingest/log', (req: Request, res: Response) => {
    const { rawText, format } = req.body || {};
    res.json({
      status: 'ingested',
      format: format || 'raw',
      parsedEvents: rawText ? String(rawText).split('\n').filter(Boolean).length : 0,
      timestamp: new Date().toISOString()
    });
  });

  app.post('/api/ingest/dataset', (req: Request, res: Response) => {
    const { recordsCount } = req.body || {};
    res.json({
      status: 'dataset_received',
      recordsProcessed: recordsCount || 5000,
      retrainedModel: 'RandomForestClassifier',
      accuracy: 0.984,
      timestamp: new Date().toISOString()
    });
  });

  const isProduction = process.env.NODE_ENV === 'production' || fs.existsSync(path.resolve(__dirname, 'dist'));

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`[AI SOC Assistant] Server listening on port ${PORT}`);
    console.log(`[AI SOC Assistant] Frontend available at root, Backend REST API available at /api/*`);
  });
}

startServer().catch(err => {
  console.error('[AI SOC Assistant] Failed to start server:', err);
});
