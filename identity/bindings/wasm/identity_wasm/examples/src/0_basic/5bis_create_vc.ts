// Copyright 2024 Fondazione Links
// SPDX-License-Identifier: Apache-2.0

import {
  Credential,
  Duration,
  FailFast,
  JwkPqMemStore,
  JwsAlgorithm,
  JwsSignatureOptions,
  JwsVerificationOptions,
  Jwt,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  JwtPresentationOptions,
  JwtPresentationValidationOptions,
  JwtPresentationValidator,
  KeyIdMemStore,
  MethodScope,
  PQJwsVerifier,
  Presentation,
  Resolver,
  Storage,
  SubjectHolderRelationship,
  Timestamp,
  IotaDocument,
  CoreDID,
} from "@iota/identity-wasm/node";

import { IotaClient } from "@iota/iota-sdk/client";
import { blake3 } from "@noble/hashes/blake3";
import { getFundedClient, createDocumentForNetwork ,  getMemstorage, NETWORK_URL } from "../util";

// ------------------ commitment helpers ------------------
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
  return toBase64Url(blake3(bytes));
}

// ------------------ timing helpers ------------------
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

/**
 * PQ VC issuance + PQ VP presentation benchmark (correct PQ presentation flow).
 */
export async function pq_with_perf() {
  const RUNS = 30;
  const WARMUP = 3;

  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();
  // ---------- metrics ----------
  const T_hash: number[] = [];
  const T_signVC: number[] = [];
  const T_validateVC: number[] = [];
  const Latency_issuance_e2e: number[] = [];
  const VC_bytes: number[] = [];

  const T_createVP: number[] = [];
  const T_validateVP_sig_only: number[] = [];
  const T_resolve_issuers: number[] = [];
  const T_validateVC_inVP: number[] = [];
  const Latency_presentation_e2e: number[] = [];
  const VP_bytes: number[] = [];

  // ===========================================================================
  // Step 1: Create identities for issuer + holder (one-time setup).
  // ===========================================================================
  const issuerStorage = new Storage(new JwkPqMemStore(), new KeyIdMemStore());
  const issuerClient = await getFundedClient(issuerStorage);
  const [unpublishedIssuerDocument, issuerFragment] = await createDocumentForNetwork(issuerStorage, network);
    const { output: issuerIdentity } = await issuerClient
    .createIdentity(unpublishedIssuerDocument)
    .finish()
    .buildAndExecute(issuerClient);
  const issuerDocument = issuerIdentity.didDocument();

  const aliceStorage = new Storage(new JwkPqMemStore(), new KeyIdMemStore());
  const aliceClient = await getFundedClient(aliceStorage);
    const [unpublishedAliceDocument, aliceFragment] = await createDocumentForNetwork(aliceStorage, network);
    const { output: aliceIdentity } = await aliceClient
      .createIdentity(unpublishedAliceDocument)
      .finish()
      .buildAndExecute(aliceClient);
    const aliceDocument = aliceIdentity.didDocument();
  // const aliceFragment = await aliceDocument.generateMethodPQC(
  //   aliceStorage,
  //   JwkPqMemStore.mldsaKeyType(),
  //   JwsAlgorithm.MLDSA44,
  //   "#0",
  //   MethodScope.VerificationMethod(),
  // );

  // Resolver (used by verifier to resolve holder/issuer DID docs)
  const resolver = new Resolver({ client: aliceClient });

  // ===========================================================================
  // Warmup + RUNS
  // ===========================================================================
  for (let r = -WARMUP; r < RUNS; r++) {
    // -------------------
    // Step 2: Issuer creates and signs a VC (with your commitment)
    // -------------------
    const tIss0 = nowNs();

    const claims = {
      name: "Alice",
      degreeName: "Bachelor of Science and Arts",
      degreeType: "BachelorDegree",
      GPA: "4.0",
    };

    const credId = "https://example.edu/credentials/3732";
    const schemaId = "https://example.edu/schemas/university-degree-v1.json";
    const version = "pqzkvc-1";

    const issuanceDate = Timestamp.nowUTC();
    const expirationDate = Timestamp.parse(new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString());

    const th0 = nowNs();
    const commitmentInput = {
      v: version,
      sub: aliceDocument.id().toString(),
      credId,
      exp: expirationDate.toString(),
      schemaId,
      claims,
    };
    const commitment = commitmentBlake3_256(commitmentInput);
    const th1 = nowNs();

    // upgraded subject (privacy-friendly)
    const subjectUpgraded = {
      id: aliceDocument.id(),
      commitment,
      v: version,
      schemaId,
    };

    const unsignedVc = new Credential({
      id: credId,
      type: ["UniversityDegreeCredential", "PQZKVC"],
      issuer: issuerDocument.id(),
      issuanceDate,
      expirationDate,
      credentialSchema: { id: schemaId, type: "JsonSchema" },
      credentialSubject: subjectUpgraded,
    });

    const ts0 = nowNs();
    const credentialJwt = await issuerDocument.createCredentialJwtPqc(
      issuerStorage,
      issuerFragment,
      unsignedVc,
      new JwsSignatureOptions(),
    );
    const ts1 = nowNs();

    const tv0 = nowNs();
    new JwtCredentialValidator(new PQJwsVerifier()).validate(
      credentialJwt,
      issuerDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError,
    );
    const tv1 = nowNs();

    const tIss1 = nowNs();

    const vcJwtStr = credentialJwt.toString();
    const vcSize = Buffer.byteLength(vcJwtStr, "utf8");

    // -------------------
    // Step 4–7: Presentation flow (correct PQ presentation)
    // -------------------
    const tPres0 = nowNs();

    const nonce = `nonce-${Date.now()}-${r}`; // unique per run
    const expires = Timestamp.nowUTC().checkedAdd(Duration.minutes(10));

    // Create VP with embedded JWT credential
    const unsignedVp = new Presentation({
      holder: aliceDocument.id(),
      verifiableCredential: [credentialJwt],
    });

    // Holder creates PQ VP JWT (nonce + expiration)
    const tCvp0 = nowNs();
    const presentationJwt = await aliceDocument.createPresentationJwtPqc(
      aliceStorage,
      aliceFragment,
      unsignedVp,
      new JwsSignatureOptions({ nonce }),
      new JwtPresentationOptions({ expirationDate: expires }),
    );
    const tCvp1 = nowNs();

    const vpJwtStr = presentationJwt.toString();
    const vpSize = Buffer.byteLength(vpJwtStr, "utf8");

    // Verifier: resolve holder DID (as in your example)
    const presentationHolderDID: CoreDID = JwtPresentationValidator.extractHolder(presentationJwt);
    const resolvedHolder = await resolver.resolve(presentationHolderDID.toString());

    // Validate VP signature + nonce (NOTE: does NOT validate embedded VCs yet)
    const tVvp0 = nowNs();
    const jwtPresentationValidationOptions = new JwtPresentationValidationOptions({
      presentationVerifierOptions: new JwsVerificationOptions({ nonce }),
    });

    const decodedPresentation = new JwtPresentationValidator(new PQJwsVerifier()).validate(
      presentationJwt,
      resolvedHolder,
      jwtPresentationValidationOptions
    );
    const tVvp1 = nowNs();

    // Extract JWT credentials from VP
    const jwtCredentials: Jwt[] = decodedPresentation
      .presentation()
      .verifiableCredential()
      .map((credential) => {
        const jwt = credential.tryIntoJwt();
        if (!jwt) throw new Error("expected a JWT credential");
        return jwt;
      });

    // Resolve issuers (can be multiple)
    const tRes0 = nowNs();
    const issuers: string[] = jwtCredentials.map((jwtCred) => {
      const issuer = JwtCredentialValidator.extractIssuerFromJwt(jwtCred);
      return issuer.toString();
    });
    const resolvedIssuers = issuers.map(() => issuerDocument); // since you know the issuer in this test
    const tRes1 = nowNs();

    // Validate embedded credential(s) (authenticity of VC signatures)
    const tVci0 = nowNs();
    const credentialValidator = new JwtCredentialValidator(new PQJwsVerifier());
    const validationOptions = new JwtCredentialValidationOptions({
      subjectHolderRelationship: [
        presentationHolderDID.toString(),
        SubjectHolderRelationship.AlwaysSubject,
      ],
    });

    for (let i = 0; i < jwtCredentials.length; i++) {
      credentialValidator.validate(
        jwtCredentials[i],
        resolvedIssuers[i],
        validationOptions,
        FailFast.FirstError,
      );
    }
    const tVci1 = nowNs();

    const tPres1 = nowNs();

    // -------------------
    // Collect metrics (skip warmup)
    // -------------------
    if (r >= 0) {
      T_hash.push(nsToMs(th1 - th0));
      T_signVC.push(nsToMs(ts1 - ts0));
      T_validateVC.push(nsToMs(tv1 - tv0));
      Latency_issuance_e2e.push(nsToMs(tIss1 - tIss0));
      VC_bytes.push(vcSize);

      T_createVP.push(nsToMs(tCvp1 - tCvp0));
      T_validateVP_sig_only.push(nsToMs(tVvp1 - tVvp0));
      T_resolve_issuers.push(nsToMs(tRes1 - tRes0));
      T_validateVC_inVP.push(nsToMs(tVci1 - tVci0));
      Latency_presentation_e2e.push(nsToMs(tPres1 - tPres0));
      VP_bytes.push(vpSize);

      console.log(
        `[run ${r}] VC: sign=${T_signVC[T_signVC.length - 1].toFixed(3)}ms ` +
        `validate=${T_validateVC[T_validateVC.length - 1].toFixed(3)}ms | ` +
        `VP: create=${T_createVP[T_createVP.length - 1].toFixed(3)}ms ` +
        `vp_sig=${T_validateVP_sig_only[T_validateVP_sig_only.length - 1].toFixed(3)}ms ` +
        `resolve_iss=${T_resolve_issuers[T_resolve_issuers.length - 1].toFixed(3)}ms ` +
        `vc_in_vp=${T_validateVC_inVP[T_validateVC_inVP.length - 1].toFixed(3)}ms`
      );
    }
  }

  // ===========================================================================
  // Summary tables (paper-ready)
  // ===========================================================================
  console.log("\n=== VC Issuance/Upgrade Performance (ms) ===");
  console.table({
    T_hash: summarize(T_hash),
    T_signVC_PQC: summarize(T_signVC),
    T_validateVC: summarize(T_validateVC),
    Latency_issuance_e2e: summarize(Latency_issuance_e2e),
  });

  console.log("\n=== VC Size (bytes) ===");
  console.table({ JWT_VC_bytes: summarize(VC_bytes) });

  console.log("\n=== Presentation Performance (ms) ===");
  console.table({
    T_createVP_PQC: summarize(T_createVP),
    T_validateVP_signature_only: summarize(T_validateVP_sig_only),
    T_resolve_issuer_docs: summarize(T_resolve_issuers),
    T_validateVC_inVP: summarize(T_validateVC_inVP),
    Latency_presentation_e2e: summarize(Latency_presentation_e2e),
  });

  console.log("\n=== Presentation Size (bytes) ===");
  console.table({ JWT_VP_bytes: summarize(VP_bytes) });

  console.log("\nVP successfully validated (all runs).");
}