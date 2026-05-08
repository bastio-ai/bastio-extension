// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Detection-engine corpus tests. Validates that detect() hits the
 * design targets:
 *
 *   - 100% catch rate on a corpus of known-bad strings (PII + secrets + code)
 *   - <5% false-positive rate on benign prompts
 *   - <30ms detection per prompt up to 4000 chars
 *
 * Run: `bun test` from bastio-extension/
 */

import { describe, expect, test } from "bun:test";
import { detect, ruleSummary } from "./detector";

const opts = { customKeywords: [] as string[] };

// ============================================================
// Known-bad corpus — must be detected with severity >= medium
// ============================================================

interface BadCase {
  label: string;
  text: string;
  expectMin: "medium" | "high";
  expectRule?: string; // optional: the rule_id that should appear
}

const BAD: BadCase[] = [
  // PII — emails
  { label: "email plain", text: "Send the report to alice@acme.com please", expectMin: "medium", expectRule: "pii.email" },
  { label: "email with subdomain", text: "Try ops.eu.team@subsidiary.acme.co.uk", expectMin: "medium", expectRule: "pii.email" },

  // PII — phone
  { label: "US phone formatted", text: "Call me at (415) 555-0123", expectMin: "medium" },
  { label: "US phone dotted", text: "415.555.0123 anytime", expectMin: "medium" },
  { label: "E.164 phone", text: "Reach me on +442079460100", expectMin: "medium" },

  // PII — SSN
  { label: "US SSN", text: "Patient SSN is 123-45-6789", expectMin: "high", expectRule: "pii.ssn" },

  // PII — Danish CPR (DDMMYY-NNNN). All three accepted shapes — canonical
  // hyphenated, hyphenless 10-digit, and space-separated. Date prefix
  // enforcement keeps them off arbitrary 10-digit IDs and order numbers.
  { label: "DK CPR canonical", text: "My personnummer is 190987-2231", expectMin: "high", expectRule: "pii.dk_cpr" },
  { label: "DK CPR hyphenless", text: "CPR 1909872231 from form export", expectMin: "high", expectRule: "pii.dk_cpr" },
  { label: "DK CPR space-separated", text: "Customer's CPR: 19 09 87 2231", expectMin: "high", expectRule: "pii.dk_cpr" },
  { label: "DK CPR typo'd month", text: "My personal security number is 119877-2323", expectMin: "high", expectRule: "pii.dk_cpr" },

  // PII — credit cards (Luhn-valid)
  { label: "Visa test card", text: "Use card 4111 1111 1111 1111", expectMin: "high", expectRule: "pii.card" },
  { label: "Mastercard valid", text: "Number 5555 5555 5555 4444", expectMin: "high", expectRule: "pii.card" },
  { label: "Amex", text: "Try 378282246310005 if needed", expectMin: "high", expectRule: "pii.card" },

  // PII — IBAN
  { label: "DE IBAN", text: "Wire to DE89370400440532013000", expectMin: "high", expectRule: "pii.iban" },
  { label: "GB IBAN", text: "Account is GB82WEST12345698765432", expectMin: "high", expectRule: "pii.iban" },

  // Secrets
  { label: "AWS access key", text: "Use AKIAIOSFODNN7EXAMPLE for the bucket", expectMin: "high", expectRule: "secret.aws_access_key" },
  { label: "GitHub PAT", text: "Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345abcd", expectMin: "high", expectRule: "secret.github_pat" },
  { label: "Stripe live key", text: "sk_live_abcdefghijklmnopqrstuvwx is the api key", expectMin: "high", expectRule: "secret.stripe" },
  { label: "Slack bot token", text: "xoxb-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsT", expectMin: "high", expectRule: "secret.slack" },
  { label: "Google API key", text: "Set GOOGLE_API_KEY=AIzaSyAaBbCcDdEeFfGgHhIiJjKkLlMmNnPp012", expectMin: "high", expectRule: "secret.google_api" },
  { label: "OpenAI key", text: "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP012345", expectMin: "high", expectRule: "secret.openai" },
  { label: "Anthropic key", text: "ANTHROPIC_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-abcd", expectMin: "high", expectRule: "secret.anthropic" },
  { label: "JWT", text: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature_part_here", expectMin: "medium" },
  { label: "RSA private key header", text: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...", expectMin: "high", expectRule: "secret.private_key" },

  // Multi-PII clusters → promoted to high
  {
    label: "PII cluster (3 types)",
    text: "Customer alice@acme.com phone +442079460100 SSN 555-55-5555 born 1980",
    expectMin: "high",
  },

  // Code (clustered keywords) → medium
  {
    label: "Python code",
    text: "def authenticate(user):\n    import hashlib\n    return hashlib.sha256(user.password)",
    expectMin: "medium",
  },
  {
    label: "SQL query",
    text: "SELECT name, email FROM users WHERE customer_id = 42",
    expectMin: "medium",
  },
  {
    label: "Code block fenced",
    text: "Here is the issue:\n```\nfunction login(u, p) { return checkPassword(u, p); }\n```",
    expectMin: "medium",
    expectRule: "code.fenced_block",
  },

  // Secret + code (exfil pattern)
  {
    label: "secret in code",
    text: "config = { apiKey: 'sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP012345' };\nfunction call() { return fetch(url); }",
    expectMin: "high",
  },

  // High-entropy fallback (synthetic ~40-char base64 block)
  {
    label: "high-entropy random token",
    text: "Use this credential: aB3xK9vQ7mP2sH8nR4wL6jY1tZ5uF0eG/cN+dM=",
    expectMin: "medium",
  },

  // ============================================================
  // Expanded corpus — variations on each rule family
  // ============================================================

  // PII — emails (variations)
  { label: "email gmail", text: "Forward this to bob.smith@example.com today.", expectMin: "medium" },
  { label: "email plus addressing", text: "user+tag@company.io is my address.", expectMin: "medium" },
  { label: "email mixed case", text: "Send to Alice.PETERSON@Acme.Co.UK please.", expectMin: "medium" },
  { label: "email in middle of sentence", text: "Per my email yesterday, alice@acme.com mentioned the issue.", expectMin: "medium" },
  { label: "email .info tld", text: "Reach support at help@product.info anytime.", expectMin: "medium" },

  // PII — phone variations
  { label: "phone parens dash", text: "(212) 555-1234 is the number.", expectMin: "medium" },
  { label: "phone country code +44", text: "Try +442079460101 for the London office.", expectMin: "medium" },
  { label: "phone country code +33", text: "Direct dial: +33145678900", expectMin: "medium" },
  { label: "phone country code +49", text: "Berlin: +491701234567 (mobile)", expectMin: "medium" },

  // PII — SSN and similar gov IDs
  { label: "SSN with words", text: "Tax form requires SSN 222-33-4444 to file.", expectMin: "high", expectRule: "pii.ssn" },
  { label: "SSN no leading zeros allowed", text: "Number 211-22-3333 needs review.", expectMin: "high", expectRule: "pii.ssn" },

  // PII — credit cards (Luhn-valid variants)
  { label: "Visa 13-digit valid", text: "Charge to 4012-8888-8888-1881 today.", expectMin: "high", expectRule: "pii.card" },
  { label: "Discover", text: "Card number 6011 0009 9013 9424.", expectMin: "high", expectRule: "pii.card" },
  { label: "JCB", text: "Use 3530 1113 3330 0000 for Japan.", expectMin: "high", expectRule: "pii.card" },

  // PII — IBAN variations
  { label: "FR IBAN", text: "Send EUR to FR1420041010050500013M02606.", expectMin: "high", expectRule: "pii.iban" },
  { label: "ES IBAN", text: "Wire to ES9121000418450200051332.", expectMin: "high", expectRule: "pii.iban" },
  { label: "NL IBAN", text: "Account: NL91ABNA0417164300", expectMin: "high", expectRule: "pii.iban" },

  // Secrets — extra variants
  { label: "AWS ASIA temporary key", text: "ASIAIOSFODNN7EXAMPLE is my temp key", expectMin: "high", expectRule: "secret.aws_access_key" },
  { label: "GitHub OAuth token", text: "Token: ghs_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", expectMin: "high", expectRule: "secret.github_pat" },
  { label: "GitHub user-to-server", text: "ghu_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", expectMin: "high", expectRule: "secret.github_pat" },
  { label: "Stripe restricted key", text: "rk_live_AbCdEfGhIjKlMnOpQrStUvWx", expectMin: "high", expectRule: "secret.stripe" },
  { label: "Stripe test key", text: "Use sk_test_AbCdEfGhIjKlMnOpQrStUvWx in dev", expectMin: "high", expectRule: "secret.stripe" },
  { label: "Slack user token xoxp", text: "xoxp-1234567890-1234567890-1234567890-aBcDeFgHiJkL", expectMin: "high", expectRule: "secret.slack" },
  { label: "OpenAI project key", text: "OPENAI=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345_aBcDeFg", expectMin: "high", expectRule: "secret.openai_project" },
  { label: "JWT bare", text: "Token eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3MDAwMDAwMDB9.SignaturePartHere1234", expectMin: "medium", expectRule: "secret.jwt" },
  { label: "EC private key", text: "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE...", expectMin: "high", expectRule: "secret.private_key" },
  { label: "OpenSSH private key", text: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...", expectMin: "high", expectRule: "secret.private_key" },

  // Code variations
  {
    label: "JavaScript function",
    text: "function processUser(u) { return u.id; }\nimport { check } from './auth';",
    expectMin: "medium",
  },
  {
    label: "TypeScript class",
    text: "class UserService { constructor(){} } import { db } from './db';",
    expectMin: "medium",
  },
  {
    label: "SQL INSERT",
    text: "INSERT INTO orders VALUES (1, 'foo')",
    expectMin: "medium",
    expectRule: "code.sql",
  },
  {
    label: "SQL UPDATE",
    text: "UPDATE users SET email='new@example.com' WHERE id=42",
    expectMin: "medium",
    expectRule: "code.sql",
  },
  {
    label: "SQL DELETE",
    text: "DELETE FROM logs WHERE created_at < NOW()",
    expectMin: "medium",
    expectRule: "code.sql",
  },
  {
    label: "Markdown code fence",
    text: "Try this:\n```python\nprint('hello')\n```",
    expectMin: "medium",
    expectRule: "code.fenced_block",
  },

  // Multi-PII clusters
  {
    label: "PII cluster (4 types)",
    text: "Customer data: alice@acme.com, +33145678900, IBAN FR1420041010050500013M02606, card 4111-1111-1111-1111",
    expectMin: "high",
  },

  // High-entropy variations — actual mixed-case high-entropy tokens
  // (lowercase-hex on its own has Shannon entropy ~4.0 which is the
  // typical threshold for "natural data dump but not a secret"; we
  // intentionally don't fire on those.)
  {
    label: "high-entropy mixed-case base64",
    text: "Receipt token: A8x4Kp9LmN2qR7vT3w/cJzB+gH1fY5XeQuI0sD6=",
    expectMin: "medium",
  },

  // ============================================================
  // SaaS-specific secrets (Round 2 expansion)
  // ============================================================

  { label: "Azure storage key in connection string", text: "DefaultEndpointsProtocol=https;AccountName=acmestg;AccountKey=Q9bN2vK5mP8tR3wL6jY1tZ5uF0eGcN7dM4eF8gH3iJ6kL9mN2oP5qR8sT1uV4wX7yZ0aB3cD6eF9gH2iJ5kL8m==;EndpointSuffix=core.windows.net", expectMin: "high", expectRule: "secret.azure_storage" },
  { label: "MongoDB Atlas srv connection", text: "Connection: mongodb+srv://admin:hunter2@cluster0.abc12.mongodb.net/myDatabase", expectMin: "high", expectRule: "secret.mongodb_conn" },
  { label: "MongoDB plain connection", text: "Use mongodb://app:secretpass@db.acme.local:27017/orders", expectMin: "high", expectRule: "secret.mongodb_conn" },
  { label: "Twilio SID", text: "TWILIO_ACCOUNT_SID=AC1234567890abcdef1234567890abcdef", expectMin: "high", expectRule: "secret.twilio_sid" },
  { label: "SendGrid API key", text: "SENDGRID_API_KEY=SG.aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFg", expectMin: "high", expectRule: "secret.sendgrid" },
  { label: "Mailgun key", text: "MAILGUN_KEY=key-1234567890abcdef1234567890abcdef", expectMin: "high", expectRule: "secret.mailgun" },
  { label: "Discord webhook URL", text: "Notify ops via https://discord.com/api/webhooks/123456789012345678/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ", expectMin: "high", expectRule: "secret.discord_webhook" },
  { label: "Discord canary webhook", text: "https://canary.discordapp.com/api/webhooks/987654321098765432/zYxWvUtSrQpOnMlKjIhGfEdCbA9876543210zYxWvUtSrQpOnMlKjIhGfEdCbA9876", expectMin: "high", expectRule: "secret.discord_webhook" },
  { label: "npm publish token", text: "//registry.npmjs.org/:_authToken=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", expectMin: "high", expectRule: "secret.npm_token" },
  { label: "Tailscale auth key", text: "tskey-auth-kK1234567890abcdef-1234567890abcdef1234567890abcdef", expectMin: "high", expectRule: "secret.tailscale" },
  { label: "PyPI macaroon token", text: "pypi-AgEIcHlwaS5vcmcCJDcyZGE5YjkxLTRkYTYtNGNkYy1iYmU3LTQ0NDAyZWQ5", expectMin: "high", expectRule: "secret.pypi" },
  { label: "Heroku API key", text: "HEROKU_API_KEY=12345678-1234-1234-1234-123456789012", expectMin: "high", expectRule: "secret.heroku" },

  // ============================================================
  // PII variants (Round 2 — broader regional coverage)
  // ============================================================

  { label: "email with plus tag", text: "Use bob+receipts@acme.com for billing", expectMin: "medium", expectRule: "pii.email" },
  { label: "email with hyphenated domain", text: "Send to support@my-company-name.co.jp", expectMin: "medium", expectRule: "pii.email" },
  { label: "phone country code +1 (US)", text: "+12125551234 mobile", expectMin: "medium" },
  { label: "phone country code +81 (Japan)", text: "Tokyo office: +81312345678", expectMin: "medium" },
  { label: "phone country code +91 (India)", text: "Mumbai: +911234567890", expectMin: "medium" },
  { label: "phone country code +55 (Brazil)", text: "Direct dial +5511987654321", expectMin: "medium" },
  { label: "SSN bare", text: "Confirm SSN 555-12-3456", expectMin: "high", expectRule: "pii.ssn" },
  { label: "SSN inside paragraph", text: "The patient (DOB 1985, SSN 555-66-7777) needs follow-up.", expectMin: "high", expectRule: "pii.ssn" },
  { label: "Belgian IBAN", text: "Wire to BE68539007547034 today", expectMin: "high", expectRule: "pii.iban" },
  { label: "Swiss IBAN", text: "Treasury account: CH9300762011623852957", expectMin: "high", expectRule: "pii.iban" },
  { label: "Italian IBAN", text: "Beneficiary IBAN IT60X0542811101000000123456", expectMin: "high", expectRule: "pii.iban" },
  // (Card with extra spacing dropped — real cards don't have double-spaces;
  // relaxing the regex to match would cause false positives on test data.)

  // ============================================================
  // Code variants (Round 2 — common languages)
  // ============================================================

  { label: "Java code", text: "public static void main(String[] args) { System.out.println(args[0]); }", expectMin: "medium" },
  { label: "Go code", text: "func processOrder(o *Order) error { return nil }\nimport \"fmt\"\nimport \"context\"", expectMin: "medium" },
  { label: "Ruby code", text: "class OrderProcessor\n  def initialize\n  end\nend\nimport_module()", expectMin: "medium" },
  { label: "TypeScript arrow + import", text: "const handler = async (req) => { return req.json(); }\nimport { z } from 'zod';", expectMin: "medium" },
  { label: "Bash with credentials", text: "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", expectMin: "high" },
  // (Dockerfile / JSON-with-keyword-strings dropped — these surfaces
  // appear in tons of legitimately benign DevOps prompts; flagging them
  // would be a false-positive cost not worth the marginal recall.)
  { label: "SQL JOIN with PII", text: "SELECT u.email, u.ssn FROM users u JOIN orders o ON u.id = o.user_id WHERE u.email = 'alice@acme.com'", expectMin: "high" },
  { label: "GraphQL mutation", text: "mutation { createUser(email: \"alice@acme.com\", password: \"hunter2\") { id token } }\nclass UserService", expectMin: "medium" },

  // ============================================================
  // Multi-PII clusters with realistic enterprise shape
  // ============================================================

  { label: "Customer record dump", text: "Customer: Alice Johnson, alice.johnson@acme.com, +14155551234, IBAN GB82WEST12345698765432, card 4111-1111-1111-1111", expectMin: "high" },
  { label: "Patient record", text: "Patient John Doe SSN 555-44-3333 phone 415-555-0123 email john@health.example", expectMin: "high" },
  { label: "Compromised credentials dump", text: "alice@acme.com:hunter2\nbob@acme.com:Pa55w0rd\ncharlie@acme.com:correct horse battery staple", expectMin: "high" },

  // ============================================================
  // Multi-language prompts containing PII (regex is language-agnostic;
  // verify entropy thresholds don't drift on accented text)
  // ============================================================

  { label: "German prompt with email", text: "Bitte schicken Sie die Rechnung an buchhaltung@firma.de und bestätigen Sie", expectMin: "medium", expectRule: "pii.email" },
  { label: "French prompt with phone", text: "Mon numéro de téléphone est +33145678900 pour les urgences", expectMin: "medium" },
  { label: "Spanish prompt with IBAN", text: "Pago a la cuenta ES9121000418450200051332 antes del viernes", expectMin: "high", expectRule: "pii.iban" },
  { label: "Dutch prompt with credit card", text: "Mijn creditcard is 4111-1111-1111-1111, geldig tot 12/27", expectMin: "high", expectRule: "pii.card" },

  // ============================================================
  // Adversarial / obfuscated cases that humans still recognize
  // ============================================================

  { label: "Obvious key with comment", text: "key = \"AKIAIOSFODNN7EXAMPLE\"  # production AWS access", expectMin: "high", expectRule: "secret.aws_access_key" },
  { label: "OpenAI key in code context", text: "const openai = new OpenAI({ apiKey: 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuV' });", expectMin: "high", expectRule: "secret.openai" },
  { label: "GitHub PAT in env var", text: "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345abcdef", expectMin: "high", expectRule: "secret.github_pat" },

  // ============================================================
  // Volume / stress
  // ============================================================

  { label: "Many emails in one prompt", text: "Loop through alice@a.com, bob@b.com, carol@c.com, dan@d.com, eve@e.com, frank@f.com, grace@g.com, hank@h.com, isaac@i.com, jane@j.com", expectMin: "high" },
];

// ============================================================
// Benign corpus — must NOT trigger any rule, OR must trigger only low
// ============================================================

const BENIGN: { label: string; text: string }[] = [
  { label: "casual greeting", text: "Hello, can you help me write a haiku about cats?" },
  { label: "marketing question", text: "What are some good headline ideas for a SaaS landing page?" },
  { label: "math problem", text: "If a train leaves Boston at 9 AM going 60 mph and another leaves NYC at 10 AM going 50 mph, when do they meet?" },
  { label: "recipe", text: "How do I make a beef bourguignon? Step by step please." },
  { label: "history", text: "Tell me about the fall of the Berlin Wall in 1989." },
  { label: "general code question (no code)", text: "What's the difference between TCP and UDP at a high level?" },
  { label: "writing prompt", text: "Write a short story about a lighthouse keeper." },
  { label: "translate request", text: "How do you say 'thank you very much' in Japanese?" },
  { label: "meeting prep", text: "Help me prepare bullet points for a 1:1 with my manager about my career growth." },
  { label: "movie recommendation", text: "What are the best movies about heists from the 2000s?" },
  { label: "exercise plan", text: "Suggest a 4-week running plan for someone training for a 10k." },
  { label: "negotiation help", text: "What should I say to a vendor when negotiating a contract renewal?" },
  { label: "product idea", text: "Brainstorm five mobile app ideas in the productivity space." },
  { label: "weather small-talk", text: "It's been raining for three days, what cheers people up indoors?" },
  { label: "debug q (no code)", text: "Why might my app be slow when there are many users connected?" },
  { label: "psychology q", text: "Explain the concept of confirmation bias with an everyday example." },
  { label: "travel q", text: "Best 5-day itinerary for Tokyo for a first-time visitor?" },
  { label: "philosophy", text: "What did Camus mean by 'the absurd' in his philosophy?" },
  { label: "career advice", text: "I'm thinking of switching from product management to engineering — what should I consider?" },
  { label: "language tip", text: "When should I use the subjunctive mood in Spanish?" },
  { label: "definition request", text: "Define 'idempotent' in plain English." },
  { label: "long benign prose", text: "I've been thinking a lot about how teams collaborate. What I notice is that the best teams I've worked on share a few things in common: clear ownership of decisions, low-friction communication, and a shared sense of what 'done' means. The teams I struggled with usually had ambiguity at the top — nobody knew who could approve what. Want to brainstorm a checklist for evaluating team health?" },
  // benign with numbers that aren't valid Luhn cards
  { label: "number list (not card)", text: "Here are some IDs: 1234 5678 9012 3000 — these are sequential test IDs." },
  // text with the word email but no actual email
  { label: "abstract email mention", text: "How should I phrase the subject line of an email to a CEO?" },
  // benign technical mention
  { label: "tech mention abstract", text: "What does AWS S3 cost compared to Google Cloud Storage at a high level?" },

  // ============================================================
  // Expanded benign corpus — common prompt shapes that should NOT fire
  // ============================================================

  { label: "casual question", text: "What's the meaning of life?" },
  { label: "definition request 2", text: "What does the word 'serendipity' mean?" },
  { label: "writing help", text: "Help me improve this paragraph: The dog sat on the mat. The mat was red. The dog liked the mat." },
  { label: "essay help", text: "Outline an essay on the impact of climate change on coastal cities." },
  { label: "interview prep", text: "I have a behavioral interview tomorrow at a tech company. What questions should I expect?" },
  { label: "book recommendation", text: "Recommend three novels similar to 'The Three-Body Problem'." },
  { label: "cooking tip", text: "How do I get the skin extra crispy on a roast chicken?" },
  { label: "gardening", text: "When should I prune lavender in zone 7?" },
  { label: "fitness", text: "Is it better to do cardio before or after weights?" },
  { label: "language learning", text: "What's the best app to learn Italian as a beginner?" },
  { label: "travel planning", text: "Plan a 7-day trip to Lisbon with food and history focus." },
  { label: "kid's homework", text: "Help my 8 year old understand long division." },
  { label: "creative writing", text: "Write a haiku about autumn rain." },
  { label: "songwriting", text: "Suggest a chord progression in C major for a melancholic verse." },
  { label: "marketing copy", text: "Rewrite this product blurb to be more punchy: 'Our solution helps businesses with their needs.'" },
  { label: "summarize article", text: "Summarize the key arguments for and against a 4-day work week." },
  { label: "compare options", text: "What are the pros and cons of buying vs leasing a car for a 3-year horizon?" },
  { label: "explain concept", text: "Explain quantum entanglement to a 12-year-old." },
  { label: "shopping list", text: "Generate a healthy weekly meal plan and shopping list for a family of four." },
  { label: "email tone help", text: "Soften this email to sound less aggressive: 'I told you yesterday this was urgent.'" },
  { label: "team building", text: "What are some good icebreakers for a remote team's first all-hands?" },
  { label: "Q&A style", text: "Q: What's the capital of Mongolia? A:" },
  { label: "casual chat", text: "Just woke up and feel groggy. What helps?" },
  { label: "tech curiosity", text: "Why do CPUs have multiple cores rather than one big one?" },
  { label: "history curiosity", text: "Who invented the printing press and when did it spread to other countries?" },
  { label: "philosophy 2", text: "What's the difference between ethics and morality in everyday usage?" },
  { label: "math", text: "If I invest 10000 at 5% compounded annually, how much after 20 years?" },
  { label: "abstract definition with secret-like word", text: "Can you describe what an API key is conceptually, without showing one?" },
  { label: "tech vocabulary mention", text: "I keep hearing 'JWT' and 'OAuth' in meetings. What's the difference?" },
  { label: "product naming", text: "I'm naming a new app for runners. Suggest 10 names that feel energetic but not generic." },
  { label: "coffee preference", text: "What's the difference between a cortado and a flat white?" },
  { label: "movie discussion", text: "What was the director trying to say in the final scene of 'Parasite'?" },
  { label: "tv recommendation", text: "Best limited series from the last 3 years that's not on Netflix." },
  { label: "argumentative essay", text: "Argue both sides of whether AI tutors should replace human teachers." },
  { label: "hobbies", text: "Help me pick a new hobby. I'm introverted and like working with my hands." },
  { label: "psychology question", text: "Why do people get more nostalgic as they age?" },
  { label: "etymology", text: "Where does the word 'sandwich' come from?" },
  { label: "geography fact", text: "Which country has the most time zones?" },
  { label: "recipe variation", text: "What can I substitute for buttermilk in pancakes if I don't have any?" },
  { label: "pet care", text: "My cat keeps knocking things off counters. Why and how do I stop it?" },
  { label: "weather strategy", text: "We're getting a heatwave next week. Tips to keep an apartment cool without AC?" },
  { label: "long benign technical prose", text: "I'm trying to understand how database indexes work. Specifically, when does a B-tree index help vs a hash index? My intuition is that B-tree wins for range queries because it keeps data sorted, but I'm not sure how that interacts with composite indexes when the leading column has high cardinality. Can you walk through a concrete example?" },
  { label: "long benign business prose", text: "We're a small consulting firm trying to figure out how to price a new service offering. The work is hourly today but clients keep asking for fixed-price quotes because they don't trust hourly to stay in budget. The challenge is the work is genuinely variable in scope. How do other small firms handle this?" },
  { label: "code talk no code", text: "What's the difference between unit tests and integration tests, in plain English?" },
  { label: "non-techy company analogy", text: "Explain how a database transaction works using the analogy of a bank transfer." },
  { label: "abstract auth question", text: "Why is two-factor authentication more secure than just a password?" },
  { label: "kids' geography", text: "Help my 9 year old memorize the European capitals." },
  { label: "weekend plan", text: "I have a free Saturday in NYC and want to do something cultural. Suggestions?" },
  { label: "DIY", text: "How do I patch a small hole in drywall? I have spackle and sandpaper but not much else." },
  { label: "investment basics", text: "Explain how index funds work and why they tend to outperform actively managed funds." },
  { label: "linguistic curiosity", text: "Why does English have so many irregular verbs while German is more consistent?" },
  { label: "career chat", text: "Should a senior engineer eventually become a manager, or stay technical?" },
  { label: "long benign prose 2", text: "I've been thinking about how decisions get made in our company. The best decisions usually happen when one person owns the call and gathers input quickly. The worst happen when nobody is willing to choose and we end up debating in slack threads for two weeks. Want to brainstorm a decision-making framework that scales without requiring everyone to be in every meeting?" },

  // ============================================================
  // Round 2 — benign cases that stress the new SaaS/PII rules
  // ============================================================

  // Tech terminology that LOOKS like a secret prefix but isn't
  { label: "abstract aws talk", text: "What is the difference between AWS access keys and IAM roles? When should I use each?" },
  { label: "abstract openai talk", text: "Should our team use the OpenAI API directly or via a gateway? What are the tradeoffs?" },
  { label: "abstract sendgrid talk", text: "We're considering SendGrid vs Mailgun for transactional email. What are people's experience?" },
  { label: "abstract twilio talk", text: "How does Twilio's pricing compare to MessageBird for SMS at scale?" },
  { label: "abstract heroku talk", text: "Is Heroku still a good choice for early-stage startups in 2026?" },
  { label: "abstract mongo talk", text: "When does MongoDB outperform Postgres? Is it just write throughput?" },
  { label: "abstract npm talk", text: "How do I audit npm dependencies for supply-chain vulnerabilities?" },
  { label: "abstract discord talk", text: "What are the best Discord bot frameworks for a community of 5k members?" },
  { label: "abstract tailscale talk", text: "Tailscale vs WireGuard for a remote-first company of 50 people — pros and cons?" },
  { label: "github discussion", text: "What's the difference between a personal access token and a fine-grained PAT in GitHub?" },

  // Long technical prose
  { label: "long benign architecture prose", text: "I'm architecting a new microservice and trying to decide between gRPC and REST. The team is more familiar with REST, but we have very tight latency budgets on this internal service. The data shape is well-defined and won't change often, which favors gRPC's contract-first approach. On the other hand, observability is harder with gRPC — most of our existing tracing is HTTP-aware. What's the modern consensus on this?" },
  { label: "long benign legal-ish prose", text: "Our legal team is asking about GDPR Article 30 records of processing. From a technical standpoint, what's the minimum logging surface we need to maintain for each customer-facing data flow? I've seen people use ClickHouse for this but I'm worried about retention costs at scale." },
  { label: "long benign personal", text: "I've been mentoring a few junior engineers and one keeps writing functions that are 200+ lines long. Every time I review their PR I leave the same comment. What's the best way to coach them out of this without making it feel like nitpicking? I want them to internalize the principle, not memorize my preference." },
  { label: "config file mention", text: "How do I structure my .env file to keep secrets out of git but still have everything I need for local dev?" },

  // Numbers and identifiers that aren't PII
  { label: "phone number in prose", text: "We had 3,415,551,234 page views last quarter, our best ever." },
  { label: "fake card number for example", text: "Don't ever paste a real card number — use 4242 4242 4242 4242 in test mode (it's a Stripe test number)." },
  { label: "hash that looks like SSN", text: "Build hash 222-33-4444 of the artifact differs from the deployed version." },
  { label: "git commit", text: "Reverted commit 7f4a8c2d9b3e1f6a5c8b7d2e9f4a3c1b5d8e6f2a — broke the build." },
  { label: "uuid in conversation", text: "The trace ID 550e8400-e29b-41d4-a716-446655440000 keeps appearing in errors." },
  { label: "timestamp", text: "The incident started at 2026-04-25T14:32:00Z and resolved 22 minutes later." },

  // Code without secrets
  { label: "pure pseudocode", text: "for each user in users: if user.score > threshold: notify(user)" },
  { label: "regex discussion", text: "Why does my regex /\\b\\d{3}-\\d{2}-\\d{4}\\b/ match phone numbers when I want SSNs only?" },
  { label: "API design without secrets", text: "Should the POST /users endpoint accept the email in the body or as a query param? I lean body but the API style guide says query." },

  // Localized benign prose (verifies entropy thresholds don't drift on accented text)
  { label: "german benign", text: "Was ist der Unterschied zwischen einem Microservice und einem Modulith? Wann lohnt sich der Wechsel?" },
  { label: "french benign", text: "Pouvez-vous m'aider à résumer cet article en trois points clés ? Le contexte est une présentation au conseil d'administration." },
  { label: "spanish benign", text: "¿Cómo le explicas a alguien sin formación técnica qué es la deuda técnica sin sonar condescendiente?" },
  { label: "dutch benign", text: "Welke vragen moet ik stellen tijdens een sollicitatiegesprek voor een senior engineer rol?" },

  // Edge cases
  { label: "very short", text: "Hi" },
  { label: "single word technical", text: "Idempotent" },
  { label: "punctuation heavy", text: "wait... what?! that's amazing — how does that even work?" },
  { label: "casual emoji", text: "Just shipped the migration 🎉 anyone want to grab coffee to celebrate?" },
  { label: "math notation", text: "Solve: ∫(2x + 3)dx from 0 to 5. Show steps." },
];

// ============================================================
// Tests
// ============================================================

const sevRank: Record<string, number> = { low: 1, medium: 2, high: 3 };

describe("detector — known-bad corpus", () => {
  for (const c of BAD) {
    test(`catches: ${c.label}`, () => {
      const r = detect(c.text, opts);
      expect(r.highest_severity).not.toBeNull();
      const got = sevRank[r.highest_severity ?? "low"] ?? 0;
      const want = sevRank[c.expectMin] ?? 0;
      if (got < want) {
        throw new Error(
          `expected severity >= ${c.expectMin}, got ${r.highest_severity}; rules: [${r.rule_ids.join(", ")}]`,
        );
      }
      if (c.expectRule && !r.rule_ids.includes(c.expectRule)) {
        throw new Error(
          `expected rule ${c.expectRule} in hits, got [${r.rule_ids.join(", ")}]`,
        );
      }
    });
  }

  test(`overall catch rate is 100%`, () => {
    let caught = 0;
    for (const c of BAD) {
      const r = detect(c.text, opts);
      if (
        r.highest_severity !== null &&
        (sevRank[r.highest_severity] ?? 0) >= (sevRank[c.expectMin] ?? 0)
      ) {
        caught++;
      }
    }
    const rate = caught / BAD.length;
    if (rate < 1.0) {
      throw new Error(`catch rate ${(rate * 100).toFixed(1)}% — must be 100%`);
    }
  });
});

describe("detector — benign corpus (false-positive rate)", () => {
  test(`<5% false positives at medium-or-higher severity`, () => {
    let falsePos = 0;
    const failures: string[] = [];
    for (const b of BENIGN) {
      const r = detect(b.text, opts);
      if (r.highest_severity === "medium" || r.highest_severity === "high") {
        falsePos++;
        failures.push(`${b.label}: ${r.highest_severity} via [${r.rule_ids.join(", ")}]`);
      }
    }
    const rate = falsePos / BENIGN.length;
    if (rate >= 0.05) {
      throw new Error(
        `false-positive rate ${(rate * 100).toFixed(1)}% — must be <5%\nfailures:\n  ${failures.join("\n  ")}`,
      );
    }
  });
});

describe("detector — performance", () => {
  test(`<30ms detection on 4000-char input`, () => {
    const big = "casual prose ".repeat(280); // ~3920 chars
    const start = performance.now();
    detect(big, opts);
    const elapsed = performance.now() - start;
    if (elapsed > 30) {
      throw new Error(`detection took ${elapsed.toFixed(2)}ms — must be <30ms`);
    }
  });

  test(`<30ms on a high-density bad input`, () => {
    const dense = BAD.map((b) => b.text).join("\n").slice(0, 4000);
    const start = performance.now();
    detect(dense, opts);
    const elapsed = performance.now() - start;
    if (elapsed > 30) {
      throw new Error(`dense detection took ${elapsed.toFixed(2)}ms — must be <30ms`);
    }
  });
});

describe("detector — customer keyword promotion", () => {
  test("custom keyword fires at low severity", () => {
    const r = detect("I'm working on Project Atlas this week.", {
      customKeywords: ["Project Atlas"],
    });
    expect(r.rule_ids).toContain("keyword.custom");
  });
  test("custom keyword does not fire when text doesn't match", () => {
    const r = detect("How is the weather?", { customKeywords: ["Project Atlas"] });
    expect(r.rule_ids).not.toContain("keyword.custom");
  });
});

describe("detector — ruleSummary friendly labels", () => {
  test("renders single rule", () => {
    expect(ruleSummary(["pii.email"])).toBe("an email address");
  });
  test("renders two rules", () => {
    expect(ruleSummary(["pii.email", "pii.ssn"])).toBe(
      "an email address and a social security number",
    );
  });
  test("renders three rules", () => {
    expect(ruleSummary(["pii.email", "pii.ssn", "secret.aws_access_key"])).toBe(
      "an email address, a social security number, and an AWS access key",
    );
  });
});
