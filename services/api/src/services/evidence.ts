import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import {
  GENESIS_HASH,
  buildReceipt,
  ed25519Signer,
  ed25519Verifier,
  newId,
  verifyChain,
  verifyReceipt,
  type Receipt,
  type ReceiptKind,
  type ReceiptSigner,
  type ReceiptVerifier,
} from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { metrics } from '../metrics.js';
import type { Config } from '../config.js';

/**
 * Evidence append.
 *
 * The chain head row is locked FOR UPDATE before a sequence number is taken,
 * so two concurrent decisions in the same tenant serialise rather than fork
 * the chain. A forked chain is an unverifiable chain, which would quietly
 * destroy the property the receipts exist to provide.
 */

export interface EvidenceKeys {
  signer: ReceiptSigner;
  verifier: ReceiptVerifier;
  keyId: string;
}

export function loadEvidenceKeys(config: Config): EvidenceKeys {
  if (config.RECEIPT_SIGNING_KEY_B64) {
    const pem = Buffer.from(config.RECEIPT_SIGNING_KEY_B64, 'base64').toString('utf8');
    const privateKey = createPrivateKey(pem);
    return {
      keyId: config.RECEIPT_SIGNING_KEY_ID,
      signer: ed25519Signer(privateKey, config.RECEIPT_SIGNING_KEY_ID),
      verifier: ed25519Verifier(createPublicKey(privateKey), config.RECEIPT_SIGNING_KEY_ID),
    };
  }
  // Development only; loadConfig refuses to start production without a key.
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    keyId: config.RECEIPT_SIGNING_KEY_ID,
    signer: ed25519Signer(privateKey, config.RECEIPT_SIGNING_KEY_ID),
    verifier: ed25519Verifier(publicKey, config.RECEIPT_SIGNING_KEY_ID),
  };
}

export interface AppendReceiptInput {
  organizationId: string;
  kind: ReceiptKind;
  payload: Record<string, unknown>;
  subjectId?: string | null;
  requestId?: string | null;
  decisionId?: string | null;
}

export async function appendReceipt(
  client: PoolClient,
  keys: EvidenceKeys,
  input: AppendReceiptInput,
): Promise<Receipt> {
  const head = await client.query(
    `SELECT seq, head_hash FROM scrutexity.receipt_chain_heads
      WHERE organization_id = $1 FOR UPDATE`,
    [input.organizationId],
  );

  const previousSeq = head.rows[0] ? Number(head.rows[0].seq) : 0;
  const previousHash: string = head.rows[0]?.head_hash ?? GENESIS_HASH;
  const seq = previousSeq + 1;

  const receipt = buildReceipt({
    id: newId('receipt'),
    organization_id: input.organizationId,
    seq,
    kind: input.kind,
    subject_id: input.subjectId ?? null,
    request_id: input.requestId ?? null,
    decision_id: input.decisionId ?? null,
    payload: input.payload,
    previous_hash: previousHash,
    created_at: new Date().toISOString(),
    signer: keys.signer,
  });

  await client.query(
    `INSERT INTO scrutexity.receipts
       (id, organization_id, seq, kind, subject_id, request_id, decision_id,
        payload, payload_hash, previous_hash, hash, signature, signing_key_id, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      receipt.id,
      receipt.organization_id,
      receipt.seq,
      receipt.kind,
      receipt.subject_id,
      receipt.request_id,
      receipt.decision_id,
      JSON.stringify(receipt.payload),
      receipt.payload_hash,
      receipt.previous_hash,
      receipt.hash,
      receipt.signature,
      receipt.signing_key_id,
      receipt.created_at,
    ],
  );

  await client.query(
    `INSERT INTO scrutexity.receipt_chain_heads (organization_id, seq, head_hash)
     VALUES ($1, $2, $3)
     ON CONFLICT (organization_id) DO UPDATE
       SET seq = EXCLUDED.seq, head_hash = EXCLUDED.head_hash, updated_at = now()`,
    [input.organizationId, receipt.seq, receipt.hash],
  );

  metrics.receiptsAppended.inc({ kind: receipt.kind });
  return receipt;
}

interface ReceiptRow {
  id: string;
  organization_id: string;
  seq: string;
  kind: ReceiptKind;
  subject_id: string | null;
  request_id: string | null;
  decision_id: string | null;
  payload: Record<string, unknown>;
  payload_hash: string;
  previous_hash: string;
  hash: string;
  signature: string | null;
  signing_key_id: string | null;
  created_at: Date;
}

export function toReceipt(row: ReceiptRow): Receipt {
  return {
    id: row.id,
    organization_id: row.organization_id,
    seq: Number(row.seq),
    kind: row.kind,
    subject_id: row.subject_id,
    request_id: row.request_id,
    decision_id: row.decision_id,
    payload: row.payload,
    payload_hash: row.payload_hash,
    previous_hash: row.previous_hash,
    hash: row.hash,
    signature: row.signature,
    signing_key_id: row.signing_key_id,
    created_at: row.created_at.toISOString(),
  };
}

export async function fetchReceipt(client: PoolClient, id: string): Promise<Receipt | null> {
  const result = await client.query('SELECT * FROM scrutexity.receipts WHERE id = $1', [id]);
  return result.rows[0] ? toReceipt(result.rows[0] as ReceiptRow) : null;
}

/**
 * Verifies a receipt together with the segment of chain that precedes it, so
 * the answer covers linkage and not only self-consistency. `depth` bounds how
 * far back a single verification call reads.
 */
export async function verifyReceiptWithChain(
  client: PoolClient,
  keys: EvidenceKeys,
  receiptId: string,
  depth = 25,
) {
  const target = await fetchReceipt(client, receiptId);
  if (!target) return null;

  const segment = await client.query(
    `SELECT * FROM scrutexity.receipts
      WHERE organization_id = $1 AND seq <= $2 AND seq > $3
      ORDER BY seq ASC`,
    [target.organization_id, target.seq, Math.max(0, target.seq - depth)],
  );
  const receipts = (segment.rows as ReceiptRow[]).map(toReceipt);

  const single = verifyReceipt(target, keys.verifier);
  const chain = verifyChain(receipts, keys.verifier);

  if (!single.intact) {
    for (const check of single.checks.filter((c) => !c.passed)) {
      metrics.verificationFailures.inc({ check: check.check });
    }
  }

  return {
    receipt: target,
    receipt_verification: single,
    chain_verification: {
      ...chain,
      // A verified segment starting above seq 1 proves linkage within the
      // segment, not that the whole chain from genesis is intact. Say which.
      covers_genesis: receipts[0]?.seq === 1,
      from_seq: receipts[0]?.seq ?? null,
      to_seq: target.seq,
    },
  };
}
