# Pension Credential Issuer

Digital pension credential issuer for the [Findynet](https://findynet.fi) demo ecosystem. Issues SD-JWT VC pension credentials via OpenID4VCI that can be scanned into EUDI Wallet, Gataca, Paradym, or any compatible wallet.

## Quick Start

```bash
cd pension-credential
npm install
npx ngrok http 3000   # in another terminal
BASE_URL=https://<id>.ngrok-free.app npm start
```

Open `https://<id>.ngrok-free.app` in your browser, fill in pension details, and scan the QR code with your wallet.

## Features

- Web frontend for entering pension holder details
- QR code generation for credential offers
- SD-JWT VC credential with selectively-disclosable pension claims
- Compatible with EUDI Wallet (`dc+sd-jwt`), Gataca, and other OpenID4VCI wallets
- Finnish pension types: Kansaneläke, Työeläke, Työkyvyttömyyseläke, Kuntoutustuki

## Credential Claims

All claims are selectively disclosable:

| Claim | Description | Example |
|-------|-------------|---------|
| `given_name` | First name | Totti |
| `family_name` | Family name | Aalto |
| `birth_date` | Date of birth | 1993-03-03 |
| `personal_id` | Henkilötunnus | 030393-995E |
| `pension_type_code` | Pension type code | KAEL |
| `pension_type_name` | Pension type (Finnish) | Kansaneläke |
| `pension_start_date` | Start date | 2024-02-01 |
| `pension_amount` | Monthly amount (€) | 835.76 |

## Configuration

| Env var    | Default                  | Description            |
|------------|--------------------------|------------------------|
| `PORT`     | `3000`                   | Server port            |
| `BASE_URL` | `http://localhost:$PORT`  | Public URL (must be HTTPS for EUDI Wallet) |
