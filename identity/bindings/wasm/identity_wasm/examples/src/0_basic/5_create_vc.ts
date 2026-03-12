// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
import {
  JwtPresentationValidator,
  JwtPresentationValidationOptions,
  Presentation,
} from "@iota/identity-wasm/node";
import {
  Credential,
  FailFast,
  JwsSignatureOptions,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  PQJwsVerifier,
  Timestamp
} from "@iota/identity-wasm/node";
import { IotaClient } from "@iota/iota-sdk/client";
import { createDocumentForNetwork, getFundedClient, getMemstorage, NETWORK_URL } from "../util";

import { blake3 } from "@noble/hashes/blake3";

function canonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(",")}]`;
  const o = obj as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`).join(",")}}`;
}

function toBase64Url(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function commitmentBlake3_256(payload: unknown, domainTag = "PQZKVC-v1"): string {
  const msg = `${domainTag}\u0000${canonicalize(payload)}`;
  const bytes = new TextEncoder().encode(msg);
  return toBase64Url(blake3(bytes)); // 32-byte digest
}

// --- helpers timing ---
function nowNs(): bigint {
  return process.hrtime.bigint();
}
function nsToMs(ns: bigint): number {
  return Number(ns) / 1e6;
}
function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return NaN;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, idx))];
}
function summarize(values: number[]) {
  const s = [...values].sort((a, b) => a - b);
  const avg = values.reduce((a, b) => a + b, 0) / values.length;
  return {
    n: values.length,
    avg: Number(avg.toFixed(3)),
    p50: Number(percentile(s, 50).toFixed(3)),
    p95: Number(percentile(s, 95).toFixed(3)),
    p99: Number(percentile(s, 99).toFixed(3)),
    min: Number(s[0].toFixed(3)),
    max: Number(s[s.length - 1].toFixed(3)),
  };
}

export async function createVC() {
  // ============================
  // CONFIG BENCH (senza cambiare struttura)
  // ============================
  const RUNS = 30;     // metti 1 se vuoi solo una run
  const WARMUP = 3;    // consigliato

  // raccogli metriche
  const tHash: number[] = [];
  const tSign: number[] = [];
  const tValidate: number[] = [];
  const tE2E: number[] = [];
  const jwtBytes: number[] = [];

  // ============================
  // Setup (come prima)
  // ============================
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();

  // ISSUER
  const issuerStorage = getMemstorage();
  const issuerClient = await getFundedClient(issuerStorage);
  const [unpublishedIssuerDocument, issuerFragment] = await createDocumentForNetwork(issuerStorage, network);
  const { output: issuerIdentity } = await issuerClient
    .createIdentity(unpublishedIssuerDocument)
    .finish()
    .buildAndExecute(issuerClient);
  const issuerDocument = issuerIdentity.didDocument();

  // HOLDER / SUBJECT (Alice)
  const aliceStorage = getMemstorage();
  const aliceClient = await getFundedClient(aliceStorage);
  const [unpublishedAliceDocument] = await createDocumentForNetwork(aliceStorage, network);
  const { output: aliceIdentity } = await aliceClient
    .createIdentity(unpublishedAliceDocument)
    .finish()
    .buildAndExecute(aliceClient);
  const aliceDocument = aliceIdentity.didDocument();

  // ============================
  // WARMUP + RUNS
  // ============================
  for (let r = -WARMUP; r < RUNS; r++) {
    const t0 = nowNs();

    // ===== 1) CLAIMS =====
    const claims = {
      name: "Alice",
      degreeName: "Bachelor of Science and Artee",
      degreeType: "BachelorDegree",
      GPA: "4.0",
    };

    // ===== 2) METADATA =====
    const credId = "https://example.edu/credentials/3732";
    const schemaId = "https://example.edu/schemas/university-degree-v1.json";
    const version = "pqzkvc-1";

    const issuanceDate = Timestamp.nowUTC();
    const expirationDate = Timestamp.parse(new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString());

    // ===== 3) HASH/COMMITMENT =====
    const th0 = nowNs();
    const commitmentInput = {
      v: version,
      sub: aliceDocument.id().toString(),
      credId,
      exp: expirationDate.toString(), // ✅ deterministico
      schemaId,
      claims,
    };

    const commitment = commitmentBlake3_256(commitmentInput);
    const th1 = nowNs();

    // ===== 4) VC UPGRADED =====
    const subjectUpgraded = {
      id: aliceDocument.id(),
      commitment,
      v: version,
      schemaId,
    };

    const unsignedUpgradedVc = new Credential({
      id: credId,
      type: ["UniversityDegreeCredential", "PQZKVC"],
      issuer: issuerDocument.id(),
      issuanceDate,
      expirationDate,
      credentialSchema: {
        id: schemaId,
        type: "JsonSchema",
      },
      credentialSubject: subjectUpgraded,
    });

    // ===== 5) FIRMA PQC =====
    const ts0 = nowNs();
    const credentialJwt = await issuerDocument.createCredentialJwtPqc(
      issuerStorage,
      issuerFragment,
      unsignedUpgradedVc,
      new JwsSignatureOptions(),
    );
    const ts1 = nowNs();

    // ===== 6) VALIDAZIONE =====
    const tv0 = nowNs();
    new JwtCredentialValidator(new PQJwsVerifier()).validate(
      credentialJwt,
      issuerDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError,
    );
    const tv1 = nowNs();

    const t1 = nowNs();

    const jwtStr = credentialJwt.toString();
    const size = Buffer.byteLength(jwtStr, "utf8");

    // se siamo in warmup, non collezioniamo
    if (r >= 0) {
      tHash.push(nsToMs(th1 - th0));
      tSign.push(nsToMs(ts1 - ts0));
      tValidate.push(nsToMs(tv1 - tv0));
      tE2E.push(nsToMs(t1 - t0));
      jwtBytes.push(size);

      // stampa per-run (puoi commentarla se ti sporca l’output)
      console.log(
        `[run ${r}] hash=${tHash[tHash.length-1].toFixed(3)}ms ` +
        `sign=${tSign[tSign.length-1].toFixed(3)}ms ` +
        `validate=${tValidate[tValidate.length-1].toFixed(3)}ms ` +
        `e2e=${tE2E[tE2E.length-1].toFixed(3)}ms ` +
        `jwt=${size}B`
      );
    }
  }

  // ============================
  // REPORT (p50/p95/p99) — pronto per paper
  // ============================
  console.log("\n=== Issuance/Upgrade Performance (ms) ===");
  console.table({
    T_hash: summarize(tHash),
    T_signPQC: summarize(tSign),
    T_validate: summarize(tValidate),
    Latency_upgrade_e2e: summarize(tE2E),
  });

  console.log("\n=== Credential size (bytes) ===");
  console.table({
    JWT_bytes: summarize(jwtBytes),
  });
}
