import express from 'express';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import QRCode from 'qrcode';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── Issuer key pair ────────────────────────────────────────────────────────
const ISSUER_KID = `pension-issuer-${crypto.randomUUID().slice(0, 8)}`;
const { publicKey: issuerPub, privateKey: issuerPriv } =
  await ES256.generateKeyPair();
const signer = await ES256.getSigner(issuerPriv);
const verifier = await ES256.getVerifier(issuerPub);

const issuerJwk = { ...issuerPub, kid: ISSUER_KID, use: 'sig', alg: 'ES256' };
const jwks = { keys: [issuerJwk] };

const sdjwt = new SDJwtVcInstance({
  signer,
  signAlg: 'ES256',
  verifier,
  hasher: digest,
  hashAlg: 'sha-256',
  saltGenerator: generateSalt,
});

// ── State ──────────────────────────────────────────────────────────────────
const offers = new Map();
const validTokens = new Set();

// ── Credential type ────────────────────────────────────────────────────────
const VCT = 'urn:findy:pension:credential:1';

// Pension types with Finnish names
const PENSION_TYPES = {
  KAEL: { code: 'KAEL', name: 'Kansaneläke', nameEn: 'National Pension' },
  TKEL: { code: 'TKEL', name: 'Työeläke', nameEn: 'Earnings-related Pension' },
  TPEL: { code: 'TPEL', name: 'Työkyvyttömyyseläke', nameEn: 'Disability Pension' },
  KUEL: { code: 'KUEL', name: 'Kuntoutustuki', nameEn: 'Rehabilitation Allowance' },
};

// ── Express app ────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

app.use((req, _res, next) => {
  console.log(`  ${req.method} ${req.path}`);
  next();
});

// ── Frontend API: create a credential offer ────────────────────────────────
app.post('/api/create-offer', async (req, res) => {
  const {
    given_name = 'Totti',
    family_name = 'Aalto',
    birth_date = '1993-03-03',
    pension_type = 'KAEL',
    pension_start_date = '2024-02-01',
    pension_amount = '835.76',
    personal_id = '030393-995E',
  } = req.body;

  const preAuthCode = crypto.randomUUID();
  const pension = PENSION_TYPES[pension_type] || PENSION_TYPES.KAEL;

  offers.set(preAuthCode, {
    given_name,
    family_name,
    birth_date,
    personal_id,
    pension_type_code: pension.code,
    pension_type_name: pension.name,
    pension_type_name_en: pension.nameEn,
    pension_start_date,
    pension_amount,
    created: Date.now(),
  });

  const offerUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${BASE_URL}/credential-offer/${preAuthCode}`)}`;

  const qrDataUrl = await QRCode.toDataURL(offerUrl, {
    width: 400,
    margin: 2,
    color: { dark: '#003580', light: '#ffffff' },
  });

  res.json({ offer_url: offerUrl, qr_data_url: qrDataUrl, code: preAuthCode });
});

// ── Credential Offer (per code) ────────────────────────────────────────────
app.get('/credential-offer/:code', (req, res) => {
  const data = offers.get(req.params.code);
  if (!data) return res.status(404).json({ error: 'offer_not_found' });

  res.json({
    credential_issuer: BASE_URL,
    credential_configuration_ids: ['PensionCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': req.params.code,
      },
    },
  });
});

// ── Credential Issuer Metadata ─────────────────────────────────────────────
app.get('/.well-known/openid-credential-issuer', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({
    credential_issuer: BASE_URL,
    authorization_servers: [BASE_URL],
    credential_endpoint: `${BASE_URL}/credential`,
    nonce_endpoint: `${BASE_URL}/nonce`,
    jwks_uri: `${BASE_URL}/jwks`,
    credential_configurations_supported: {
      PensionCredential: {
        format: 'dc+sd-jwt',
        vct: VCT,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ['ES256'] },
        },
        credential_metadata: {
          display: [
            { name: 'Eläketodistus', locale: 'fi', description: 'Digitaalinen eläketodistus' },
            { name: 'Pension Credential', locale: 'en', description: 'Digital pension credential' },
          ],
          claims: [
            { path: ['given_name'], mandatory: true, display: [{ name: 'Etunimi', locale: 'fi' }, { name: 'Given Name', locale: 'en' }] },
            { path: ['family_name'], mandatory: true, display: [{ name: 'Sukunimi', locale: 'fi' }, { name: 'Family Name', locale: 'en' }] },
            { path: ['birth_date'], mandatory: true, display: [{ name: 'Syntymäaika', locale: 'fi' }, { name: 'Date of Birth', locale: 'en' }] },
            { path: ['personal_id'], mandatory: true, display: [{ name: 'Henkilötunnus', locale: 'fi' }, { name: 'Personal ID', locale: 'en' }] },
            { path: ['pension_type_code'], mandatory: true, display: [{ name: 'Eläkelaji', locale: 'fi' }, { name: 'Pension Type', locale: 'en' }] },
            { path: ['pension_type_name'], mandatory: true, display: [{ name: 'Eläkelajin nimi', locale: 'fi' }, { name: 'Pension Type Name', locale: 'en' }] },
            { path: ['pension_start_date'], mandatory: true, display: [{ name: 'Alkamispäivä', locale: 'fi' }, { name: 'Start Date', locale: 'en' }] },
            { path: ['pension_amount'], mandatory: false, display: [{ name: 'Eläkkeen määrä (€/kk)', locale: 'fi' }, { name: 'Pension Amount (€/mo)', locale: 'en' }] },
          ],
        },
      },
    },
  }));
});

// ── JWKS ───────────────────────────────────────────────────────────────────
app.get('/jwks', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(jwks));
});

// ── JWT VC / Issuer Metadata ───────────────────────────────────────────────
app.get('/.well-known/jwt-vc-issuer', (_req, res) => {
  res.json({ issuer: BASE_URL, jwks_uri: `${BASE_URL}/jwks` });
});
app.get('/.well-known/jwt-issuer', (_req, res) => {
  res.json({ issuer: BASE_URL, jwks_uri: `${BASE_URL}/jwks` });
});

// ── Authorization Server Metadata ──────────────────────────────────────────
function authServerMetadata() {
  return {
    issuer: BASE_URL,
    token_endpoint: `${BASE_URL}/token`,
    response_types_supported: [],
    grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    'pre-authorized_grant_anonymous_access_supported': true,
    token_endpoint_auth_methods_supported: ['none', 'attest_jwt_client_auth'],
    client_attestation_signing_alg_values_supported: ['ES256'],
    client_attestation_pop_signing_alg_values_supported: ['ES256'],
  };
}
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(authServerMetadata()));
});
app.get('/.well-known/openid-configuration', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(authServerMetadata()));
});

// ── Token Endpoint ─────────────────────────────────────────────────────────
app.post('/token', (req, res) => {
  const code =
    req.body['pre-authorized_code'] ||
    req.body['pre_authorized_code'] ||
    req.query['pre-authorized_code'];

  if (!code || !offers.has(code)) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const accessToken = crypto.randomUUID();
  validTokens.add(accessToken);
  // Store which offer this token belongs to
  validTokens[accessToken] = code;

  console.log(`  -> token issued for offer ${code.slice(0, 8)}...`);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86400,
  });
});

// ── Nonce Endpoint ─────────────────────────────────────────────────────────
app.post('/nonce', (_req, res) => {
  const nonce = crypto.randomUUID();
  res.json({ c_nonce: nonce });
});

// ── Credential Endpoint ────────────────────────────────────────────────────
app.post('/credential', async (req, res) => {
  console.log('  -> credential body:', JSON.stringify(req.body));

  const auth = req.headers.authorization || '';
  const token = auth.replace(/^(Bearer|DPoP)\s+/i, '');
  if (!validTokens.has(token)) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  // Find the offer data for this token
  const offerCode = validTokens[token];
  const offerData = offerCode ? offers.get(offerCode) : null;
  const data = offerData || {
    given_name: 'Totti', family_name: 'Aalto', birth_date: '1993-03-03',
    personal_id: '030393-995E', pension_type_code: 'KAEL',
    pension_type_name: 'Kansaneläke', pension_type_name_en: 'National Pension',
    pension_start_date: '2024-02-01', pension_amount: '835.76',
  };

  let cnf;
  try {
    const proofJwt = req.body.proofs?.jwt?.[0] || req.body.proof?.jwt;
    if (!proofJwt) throw new Error('no proof jwt in request');
    const headerB64 = proofJwt.split('.')[0];
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    if (header.jwk) cnf = { jwk: header.jwk };
    else if (header.kid) cnf = { kid: header.kid };
    else throw new Error('proof header has neither jwk nor kid');
  } catch (e) {
    return res.status(400).json({
      error: 'invalid_proof',
      error_description: e.message,
      c_nonce: crypto.randomUUID(),
      c_nonce_expires_in: 86400,
    });
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const credential = await sdjwt.issue(
      {
        iss: BASE_URL,
        iat: now,
        exp: now + 365 * 24 * 60 * 60,
        vct: VCT,
        cnf,
        given_name: data.given_name,
        family_name: data.family_name,
        birth_date: data.birth_date,
        personal_id: data.personal_id,
        pension_type_code: data.pension_type_code,
        pension_type_name: data.pension_type_name,
        pension_start_date: data.pension_start_date,
        pension_amount: data.pension_amount,
      },
      {
        _sd: [
          'given_name', 'family_name', 'birth_date', 'personal_id',
          'pension_type_code', 'pension_type_name',
          'pension_start_date', 'pension_amount',
        ],
      },
      { header: { typ: 'dc+sd-jwt', kid: ISSUER_KID } },
    );

    console.log(`  -> pension credential issued for ${data.given_name} ${data.family_name}`);

    res.json({ credentials: [{ credential }] });
  } catch (err) {
    console.error('  -> issuance error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── Debug ──────────────────────────────────────────────────────────────────
app.get('/debug', (_req, res) => {
  res.json({
    base_url: BASE_URL,
    is_https: BASE_URL.startsWith('https://'),
    issuer_kid: ISSUER_KID,
    active_offers: offers.size,
    active_tokens: validTokens.size,
  });
});

// ── Catch-all ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  console.log(`  -> 404: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: 'not_found' });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║          Pension Credential Issuer (Findynet)           ║
╚══════════════════════════════════════════════════════════╝

  Server:     ${BASE_URL}
  Frontend:   ${BASE_URL}/
  JWKS:       ${BASE_URL}/jwks
  Debug:      ${BASE_URL}/debug
  Issuer kid: ${ISSUER_KID}
${!BASE_URL.startsWith('https://') ? '\n  ⚠ EUDI Wallet requires HTTPS. Use ngrok:\n    npx ngrok http ' + PORT + '\n    BASE_URL=https://<id>.ngrok-free.app npm start\n' : ''}
`);
});
