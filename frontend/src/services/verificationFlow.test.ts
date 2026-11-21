import { describe, expect, it, vi } from 'vitest'
import {
  buildVerificationDetails,
  runVerificationFlow,
  verifyUploadedVideo,
} from './verificationFlow'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'

vi.mock('./verificationService', () => ({
  extractMetadata: vi.fn(),
  fetchProofEventsByVideo: vi.fn(),
  getOnChainProof: vi.fn(),
}))

describe('verificationFlow – buildVerificationDetails', () => {
  const VALID_HASH = 'a'.repeat(64)
  const METADATA_HASH = 'b'.repeat(64)
  const PROOF_ID = '0x' + 'c'.repeat(64)

  const ACTIVE_CHAIN_PROOF: ChainProofRecord = {
    videoHash: VALID_HASH,
    metadataHash: METADATA_HASH,
    status: 1,
    tier: 1,
    createdAt: '1700000000',
    expiresAt: 0,
    issuer: 'GBISSUER',
    source: 'GBSOURCE',
  }

  const SAMPLE_EVENT: ProofEvent = {
    id: 1,
    event_type: 'registered',
    file_name: 'test.mp4',
    video_hash: VALID_HASH,
    proof_id: PROOF_ID,
    tier: 'silent',
    created_at: '2026-10-19T00:00:00Z',
  }

  it('builds complete details for a confirmed verification result', () => {
    const details = buildVerificationDetails({
      videoHash: VALID_HASH,
      hasHarpocratesMetadata: true,
      events: [SAMPLE_EVENT],
      onChain: ACTIVE_CHAIN_PROOF,
      proofId: PROOF_ID,
      metadataHash: METADATA_HASH,
    })

    expect(details.publicInputChecks.length).toBeGreaterThanOrEqual(3)
    const hashCheck = details.publicInputChecks.find((c) => c.id === 'video-hash')
    expect(hashCheck?.status).toBe('passed')
    expect(hashCheck?.value).toBe(VALID_HASH)

    const metaCheck = details.publicInputChecks.find((c) => c.id === 'metadata-envelope')
    expect(metaCheck?.status).toBe('passed')

    const bindingCheck = details.publicInputChecks.find((c) => c.id === 'metadata-binding')
    expect(bindingCheck?.status).toBe('passed')

    const statusObs = details.chainObservations.find((o) => o.id === 'chain-status')
    expect(statusObs?.status).toBe('passed')
    expect(statusObs?.value).toContain('Confirmed')

    const primaryReason = details.trustReasons.find((r) => r.id === 'primary-decision')
    expect(primaryReason?.status).toBe('passed')
    expect(primaryReason?.description).toMatch(/corroborated by database and active chain/i)
  })

  it('flags boundary failure when on-chain proof is revoked', () => {
    const revokedProof: ChainProofRecord = {
      ...ACTIVE_CHAIN_PROOF,
      status: 2,
    }

    const details = buildVerificationDetails({
      videoHash: VALID_HASH,
      hasHarpocratesMetadata: true,
      events: [SAMPLE_EVENT],
      onChain: revokedProof,
      errorCode: 'REVOKED_EVIDENCE',
    })

    const statusObs = details.chainObservations.find((o) => o.id === 'chain-status')
    expect(statusObs?.status).toBe('failed')
    expect(statusObs?.value).toBe('Revoked')

    const primaryReason = details.trustReasons.find((r) => r.id === 'primary-decision')
    expect(primaryReason?.status).toBe('failed')
    expect(primaryReason?.description).toMatch(/revoked/i)
  })

  it('flags boundary failure when on-chain proof is expired', () => {
    const expiredProof: ChainProofRecord = {
      ...ACTIVE_CHAIN_PROOF,
      status: 3,
      expiresAt: 1600000000,
    }

    const details = buildVerificationDetails({
      videoHash: VALID_HASH,
      hasHarpocratesMetadata: true,
      events: [SAMPLE_EVENT],
      onChain: expiredProof,
      errorCode: 'EXPIRED_EVIDENCE',
    })

    const statusObs = details.chainObservations.find((o) => o.id === 'chain-status')
    expect(statusObs?.status).toBe('failed')
    expect(statusObs?.value).toBe('Expired')

    const primaryReason = details.trustReasons.find((r) => r.id === 'primary-decision')
    expect(primaryReason?.status).toBe('failed')
    expect(primaryReason?.description).toMatch(/expired/i)
  })

  it('detects metadata envelope mismatch (tampering) boundary case', () => {
    const details = buildVerificationDetails({
      videoHash: VALID_HASH,
      hasHarpocratesMetadata: true,
      events: [SAMPLE_EVENT],
      onChain: ACTIVE_CHAIN_PROOF,
      metadataHash: 'd'.repeat(64), // Mismatch with ACTIVE_CHAIN_PROOF.metadataHash
      errorCode: 'METADATA_ENVELOPE_MISMATCH',
    })

    const bindingCheck = details.publicInputChecks.find((c) => c.id === 'metadata-binding')
    expect(bindingCheck?.status).toBe('failed')
    expect(bindingCheck?.summary).toMatch(/mismatch/i)

    const primaryReason = details.trustReasons.find((r) => r.id === 'primary-decision')
    expect(primaryReason?.status).toBe('failed')
    expect(primaryReason?.description).toMatch(/tampered/i)
  })

  it('handles invalid or non-hex public video hash input', () => {
    const details = buildVerificationDetails({
      videoHash: 'invalid-non-hex-hash',
    })

    const hashCheck = details.publicInputChecks.find((c) => c.id === 'video-hash')
    expect(hashCheck?.status).toBe('failed')
    expect(hashCheck?.summary).toMatch(/malformed/i)

    const fpReason = details.trustReasons.find((r) => r.id === 'fingerprint-integrity')
    expect(fpReason?.status).toBe('failed')
  })

  it('handles offline local verification boundary case with no network calls', () => {
    const details = buildVerificationDetails({
      videoHash: VALID_HASH,
      hasHarpocratesMetadata: true,
      offline: true,
    })

    const statusObs = details.chainObservations.find((o) => o.id === 'chain-status')
    expect(statusObs?.value).toBe('Not checked (offline mode)')
    expect(statusObs?.status).toBe('info')

    const eventObs = details.chainObservations.find((o) => o.id === 'chain-events')
    expect(eventObs?.value).toBe('Not queried (offline mode)')

    const primaryReason = details.trustReasons.find((r) => r.id === 'primary-decision')
    expect(primaryReason?.status).toBe('info')
    expect(primaryReason?.description).toMatch(/offline/i)
  })

  it('handles uncorroborated or empty verification inputs safely', () => {
    const details = buildVerificationDetails({
      videoHash: '',
      hasHarpocratesMetadata: false,
    })

    const hashCheck = details.publicInputChecks.find((c) => c.id === 'video-hash')
    expect(hashCheck?.status).toBe('failed')

    const primaryReason = details.trustReasons.find((r) => r.id === 'primary-decision')
    expect(primaryReason?.status).toBe('failed')
  })
})

describe('verificationFlow – runVerificationFlow & verifyUploadedVideo', () => {
  const VALID_HASH = '1'.repeat(64)

  it('runVerificationFlow attaches structured details to result', async () => {
    const { fetchProofEventsByVideo, getOnChainProof } = await import('./verificationService')
    vi.mocked(fetchProofEventsByVideo).mockResolvedValueOnce([])
    vi.mocked(getOnChainProof).mockResolvedValueOnce(null)

    const result = await runVerificationFlow(VALID_HASH)

    expect(result.videoHash).toBe(VALID_HASH)
    expect(result.publicInputChecks).toBeDefined()
    expect(result.chainObservations).toBeDefined()
    expect(result.trustReasons).toBeDefined()
    expect(result.details).toBeDefined()
    expect(result.details.publicInputChecks).toEqual(result.publicInputChecks)
  })

  it('verifyUploadedVideo extracts metadata and returns full details', async () => {
    const { extractMetadata, fetchProofEventsByVideo, getOnChainProof } = await import('./verificationService')
    vi.mocked(extractMetadata).mockResolvedValueOnce({ hasHarpocratesMetadata: true })
    vi.mocked(fetchProofEventsByVideo).mockResolvedValueOnce([])
    vi.mocked(getOnChainProof).mockResolvedValueOnce(null)

    const fakeFile = new File(['data'], 'test.mp4', { type: 'video/mp4' })
    const result = await verifyUploadedVideo(fakeFile, VALID_HASH)

    expect(result.hasHarpocratesMetadata).toBe(true)
    expect(result.details.publicInputChecks.find((c) => c.id === 'metadata-envelope')?.status).toBe('passed')
  })
})
