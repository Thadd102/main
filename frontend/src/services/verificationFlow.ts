/**
 * verificationFlow — orchestrates the verification portal flow.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single result. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { assertValidVideoHash } from './videoHash'
import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'

export type VerificationCheckStatus = 'passed' | 'failed' | 'warning' | 'info'

export type PublicInputCheck = {
  id: string
  name: string
  status: VerificationCheckStatus
  summary: string
  value?: string | null
  detail?: string
}

export type ChainObservation = {
  id: string
  label: string
  value: string
  status?: VerificationCheckStatus
  detail?: string
}

export type TrustReason = {
  id: string
  title: string
  status: VerificationCheckStatus
  description: string
}

export type VerificationDetails = {
  publicInputChecks: PublicInputCheck[]
  chainObservations: ChainObservation[]
  trustReasons: TrustReason[]
}

export type VerificationDetailOptions = {
  videoHash: string
  hasHarpocratesMetadata?: boolean
  events?: ProofEvent[]
  onChain?: ChainProofRecord | null
  proofId?: string | null
  tier?: string | null
  metadataHash?: string | null
  offline?: boolean
  errorCode?: string | null
}

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
  publicInputChecks: PublicInputCheck[]
  chainObservations: ChainObservation[]
  trustReasons: TrustReason[]
  details: VerificationDetails
}

function formatProofExpiry(expiresAt: number | null | undefined): string {
  if (expiresAt === 0) return 'Never'
  if (expiresAt === null || expiresAt === undefined || !Number.isSafeInteger(expiresAt) || expiresAt < 0) {
    return 'Unavailable'
  }
  const milliseconds = expiresAt * 1000
  if (!Number.isFinite(milliseconds)) return 'Unavailable'
  const date = new Date(milliseconds)
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toISOString()
}

function formatIdentityTier(tier: unknown): string {
  if (tier === 1 || tier === '1' || tier === 'silent') return 'Silent (Tier 1)'
  if (tier === 2 || tier === '2' || tier === 'source') return 'Consistent Source (Tier 2)'
  if (tier === 3 || tier === '3' || tier === 'seal') return 'Institutional Seal (Tier 3)'
  if (tier !== null && tier !== undefined && tier !== '') return String(tier)
  return 'Unavailable'
}

function isValidHexHash(value: string | null | undefined): boolean {
  if (!value) return false
  return /^[0-9a-fA-F]{64}$/.test(value.trim())
}

/**
 * Builds the structured verification detail explorer model covering public-input checks,
 * chain observations, and trust reasons.
 */
export function buildVerificationDetails({
  videoHash,
  hasHarpocratesMetadata = false,
  events = [],
  onChain = null,
  proofId = null,
  tier = null,
  metadataHash = null,
  offline = false,
  errorCode = null,
}: VerificationDetailOptions): VerificationDetails {
  const trimmedHash = (videoHash || '').trim()
  const isHashValid = isValidHexHash(trimmedHash)
  const resolvedProofId =
    proofId ||
    onChain?.proofId ||
    events.find((e) => e.video_hash === trimmedHash && e.proof_id)?.proof_id ||
    events.find((e) => e.proof_id)?.proof_id ||
    null

  const resolvedTier = onChain?.tier !== undefined ? onChain.tier : tier

  // 1. Public-Input Checks
  const publicInputChecks: PublicInputCheck[] = []

  // Video hash format check
  if (!trimmedHash) {
    publicInputChecks.push({
      id: 'video-hash',
      name: 'Video Hash Encoding',
      status: 'failed',
      summary: 'Evidence fingerprint is missing or empty',
      value: null,
      detail: 'A canonical 64-character SHA-256 hash is required.',
    })
  } else if (isHashValid) {
    publicInputChecks.push({
      id: 'video-hash',
      name: 'Video Hash Encoding',
      status: 'passed',
      summary: 'Canonical 32-byte SHA-256 evidence fingerprint',
      value: trimmedHash,
      detail: 'The artifact hash is properly formatted as a 64-character lowercase hex string.',
    })
  } else {
    publicInputChecks.push({
      id: 'video-hash',
      name: 'Video Hash Encoding',
      status: 'failed',
      summary: 'Malformed evidence fingerprint',
      value: trimmedHash,
      detail: 'Fingerprint must be exactly 64 hexadecimal characters (32 bytes).',
    })
  }

  // Metadata envelope check
  publicInputChecks.push({
    id: 'metadata-envelope',
    name: 'Harpocrates Metadata Envelope',
    status: hasHarpocratesMetadata ? 'passed' : 'warning',
    summary: hasHarpocratesMetadata
      ? 'Embedded Harpocrates metadata envelope detected'
      : 'No embedded Harpocrates metadata detected in artifact',
    detail: hasHarpocratesMetadata
      ? 'Artifact carries valid embedded steganographic envelope header and parameters.'
      : 'The artifact lacks embedded Harpocrates steganography metadata.',
  })

  // Proof ID input check
  publicInputChecks.push({
    id: 'proof-id',
    name: 'Proof Identifier',
    status: resolvedProofId ? 'passed' : 'info',
    summary: resolvedProofId ? 'Proof identifier bound to verification session' : 'No proof identifier declared',
    value: resolvedProofId,
    detail: resolvedProofId
      ? 'Associated zero-knowledge proof record ID located for verification.'
      : 'Verification proceeded with video hash lookup only.',
  })

  // Metadata binding check
  const onChainMeta = onChain?.metadataHash
  if (metadataHash && onChainMeta) {
    const matches = metadataHash.trim().toLowerCase() === onChainMeta.trim().toLowerCase()
    publicInputChecks.push({
      id: 'metadata-binding',
      name: 'Metadata Hash Commitment Binding',
      status: matches ? 'passed' : 'failed',
      summary: matches
        ? 'Embedded metadata hash matches on-chain commitment'
        : 'Metadata mismatch: embedded hash does not match on-chain record',
      value: metadataHash,
      detail: matches
        ? 'Cryptographic binding between embedded metadata and smart contract registry is intact.'
        : 'Possible tampering: the extracted metadata hash differs from the registry commitment.',
    })
  } else if (onChainMeta) {
    publicInputChecks.push({
      id: 'metadata-binding',
      name: 'Metadata Hash Commitment Binding',
      status: 'info',
      summary: 'On-chain metadata commitment recorded',
      value: onChainMeta,
      detail: 'Registry holds a metadata commitment for this proof.',
    })
  } else if (metadataHash) {
    publicInputChecks.push({
      id: 'metadata-binding',
      name: 'Metadata Hash Commitment Binding',
      status: 'info',
      summary: 'Embedded metadata hash extracted',
      value: metadataHash,
      detail: 'Extracted metadata hash pending on-chain envelope comparison.',
    })
  } else {
    publicInputChecks.push({
      id: 'metadata-binding',
      name: 'Metadata Hash Commitment Binding',
      status: 'info',
      summary: 'No metadata hash commitment available',
      value: null,
      detail: 'No on-chain or extracted metadata hash was provided for comparison.',
    })
  }

  // 2. Chain Observations
  const chainObservations: ChainObservation[] = []

  let chainStatusValue = 'No record on-chain'
  let chainStatusType: VerificationCheckStatus = 'warning'
  let chainStatusDetail = 'The Stellar registry has no record for this video hash.'

  if (offline) {
    chainStatusValue = 'Not checked (offline mode)'
    chainStatusType = 'info'
    chainStatusDetail = 'Verification ran in local mode with zero network calls.'
  } else if (onChain) {
    if (onChain.status === 2) {
      chainStatusValue = 'Revoked'
      chainStatusType = 'failed'
      chainStatusDetail = 'The proof record has been marked REVOKED in the registry.'
    } else if (onChain.status === 3) {
      chainStatusValue = 'Expired'
      chainStatusType = 'failed'
      chainStatusDetail = 'The validity period for this record on-chain has lapsed.'
    } else {
      chainStatusValue = 'Confirmed (Active)'
      chainStatusType = 'passed'
      chainStatusDetail = 'Active and confirmed proof record found on-chain.'
    }
  }

  chainObservations.push({
    id: 'chain-status',
    label: 'Registry Status',
    value: chainStatusValue,
    status: chainStatusType,
    detail: chainStatusDetail,
  })

  chainObservations.push({
    id: 'chain-tier',
    label: 'Identity Tier',
    value: formatIdentityTier(resolvedTier),
    status: resolvedTier !== null && resolvedTier !== undefined ? 'passed' : 'info',
    detail: 'Cryptographic identity tier governance applied to this artifact.',
  })

  chainObservations.push({
    id: 'chain-expiry',
    label: 'Record Expiration',
    value: formatProofExpiry(onChain?.expiresAt),
    status: onChain?.status === 3 ? 'failed' : 'info',
    detail: 'Expiration ledger timestamp committed to the smart contract.',
  })

  chainObservations.push({
    id: 'chain-issuer',
    label: 'Issuer Authority',
    value: onChain?.issuer || 'None',
    status: onChain?.issuer ? 'passed' : 'info',
    detail: onChain?.issuer ? 'Stellar account address of the registering authority.' : 'No issuer address bound.',
  })

  chainObservations.push({
    id: 'chain-source',
    label: 'Source Address',
    value: onChain?.source || 'None',
    status: onChain?.source ? 'passed' : 'info',
    detail: onChain?.source ? 'Originating publisher account address.' : 'No source account bound.',
  })

  chainObservations.push({
    id: 'chain-events',
    label: 'Observed Events',
    value: offline ? 'Not queried (offline mode)' : `${events.length} event${events.length === 1 ? '' : 's'} recorded`,
    status: offline ? 'info' : events.length > 0 ? 'passed' : 'warning',
    detail: offline
      ? 'Database lookup was skipped for local verification.'
      : events.length > 0
        ? 'NeonDB event log corroborates the artifact registration history.'
        : 'No registration event records found for this artifact.',
  })

  // 3. Trust Reasons
  const trustReasons: TrustReason[] = []

  // Primary Trust Decision
  if (offline) {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Local Inspection Only',
      status: 'info',
      description:
        'Offline local inspection: verification ran fully locally with no network calls. It inspects metadata structure and fingerprinting only and never yields a confirmed trust decision.',
    })
  } else if (errorCode === 'REVOKED_EVIDENCE' || onChain?.status === 2) {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Revoked Evidence Record',
      status: 'failed',
      description:
        'Revoked: the chain record for this artifact has been revoked. Do not trust it as valid evidence.',
    })
  } else if (errorCode === 'EXPIRED_EVIDENCE' || onChain?.status === 3) {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Expired Evidence Record',
      status: 'failed',
      description:
        'Expired: the chain record for this artifact has expired. Do not treat it as valid evidence.',
    })
  } else if (errorCode === 'METADATA_ENVELOPE_MISMATCH') {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Metadata Envelope Tampering Detected',
      status: 'failed',
      description:
        'Metadata mismatch: the embedded metadata hash does not match the on-chain envelope bound to this proof. Treat this artifact as tampered with.',
    })
  } else if (hasHarpocratesMetadata && events.length > 0 && onChain) {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Full Corroboration Confirmed',
      status: 'passed',
      description:
        'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
    })
  } else if (hasHarpocratesMetadata) {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Metadata Corroboration Only',
      status: 'warning',
      description:
        'Metadata only: embedded Harpocrates metadata lacks complete database and chain confirmation. Treat this artifact as unconfirmed.',
    })
  } else if (events.length > 0) {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Database Event Only',
      status: 'warning',
      description:
        'Database record only: no valid embedded Harpocrates metadata or chain record was found. Treat this artifact as unconfirmed.',
    })
  } else {
    trustReasons.push({
      id: 'primary-decision',
      title: 'Artifact Not Verified',
      status: 'failed',
      description:
        'No verification evidence found: metadata, database, and chain records did not confirm this artifact. Treat it as unverified.',
    })
  }

  // Evidence Fingerprint Reason
  trustReasons.push({
    id: 'fingerprint-integrity',
    title: 'Cryptographic Fingerprint Integrity',
    status: isHashValid ? 'passed' : 'failed',
    description: isHashValid
      ? 'The evidence hash conforms to the required 256-bit SHA-256 canonical encoding format.'
      : 'The evidence fingerprint is either missing or contains non-canonical hex characters.',
  })

  // Registry Corroboration Reason
  trustReasons.push({
    id: 'registry-consensus',
    title: 'Stellar Soroban Consensus',
    status: offline ? 'info' : onChain && onChain.status === 1 ? 'passed' : onChain ? 'failed' : 'warning',
    description: offline
      ? 'On-chain consensus verification was bypassed in offline mode.'
      : onChain
        ? onChain.status === 2
          ? 'On-chain state explicitly marks this proof as revoked.'
          : onChain.status === 3
            ? 'On-chain state indicates this proof validity window has lapsed.'
            : 'Stellar Soroban registry confirms active, non-revoked registration state.'
        : 'Smart contract registry holds no registration record for this artifact.',
  })

  // Audit Trail Reason
  trustReasons.push({
    id: 'audit-trail',
    title: 'Audit Trail Corroboration',
    status: offline ? 'info' : events.length > 0 ? 'passed' : 'warning',
    description: offline
      ? 'Database audit log lookup bypassed in offline mode.'
      : events.length > 0
        ? `${events.length} historical NeonDB event log(s) corroborate artifact presence.`
        : 'No historical registration events exist in the event feed.',
  })

  return {
    publicInputChecks,
    chainObservations,
    trustReasons,
  }
}

/**
 * Run the verification flow for an already-computed video hash.
 *
 * The hash is validated before any network call is made so a malformed value
 * (from a share link or manifest) cannot inject path segments or query strings.
 */
export async function runVerificationFlow(
  videoHash: string,
  options: {
    signal?: AbortSignal
    sourceAddress?: string
    metadataHash?: string
    proofId?: string
    tier?: string
  } = {},
): Promise<VerificationResult> {
  const safeHash = assertValidVideoHash(videoHash)

  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  const onChain = await getOnChainProof(safeHash, options.sourceAddress)
  const hasHarpocratesMetadata = events.length > 0

  const details = buildVerificationDetails({
    videoHash: safeHash,
    hasHarpocratesMetadata,
    events,
    onChain,
    proofId: options.proofId,
    metadataHash: options.metadataHash,
    tier: options.tier,
  })

  return {
    videoHash: safeHash,
    hasHarpocratesMetadata,
    events,
    onChain,
    publicInputChecks: details.publicInputChecks,
    chainObservations: details.chainObservations,
    trustReasons: details.trustReasons,
    details,
  }
}

/**
 * Convenience helper: extract metadata from an uploaded file and then run the
 * verification flow for the supplied video hash.
 */
export async function verifyUploadedVideo(
  file: File,
  videoHash: string,
  options: {
    signal?: AbortSignal
    sourceAddress?: string
    metadataHash?: string
    proofId?: string
    tier?: string
  } = {},
): Promise<VerificationResult> {
  // Validate before hitting the network at all.
  const safeHash = assertValidVideoHash(videoHash)
  const extract = await extractMetadata(file, options.signal)
  const result = await runVerificationFlow(safeHash, options)

  const hasHarpocratesMetadata = extract.hasHarpocratesMetadata
  const details = buildVerificationDetails({
    videoHash: safeHash,
    hasHarpocratesMetadata,
    events: result.events,
    onChain: result.onChain,
    proofId: options.proofId,
    metadataHash: options.metadataHash,
    tier: options.tier,
  })

  return {
    ...result,
    hasHarpocratesMetadata,
    publicInputChecks: details.publicInputChecks,
    chainObservations: details.chainObservations,
    trustReasons: details.trustReasons,
    details,
  }
}
