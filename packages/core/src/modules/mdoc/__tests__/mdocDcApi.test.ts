import { getAgentOptions } from '../../../../tests'
import { Agent } from '../../../agent/Agent'
import { PublicJwk } from '../../kms'
import { X509Service } from '../../x509'
import { Mdoc } from '../Mdoc'
import { MdocDeviceResponse } from '../MdocDeviceResponse'

// Reader ECDH key (P-256) — used for HPKE encryption
const READER_PRIVATE_JWK_P256 = {
  kty: 'EC' as const,
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  crv: 'P-256' as const,
  d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
}

describe('mdoc DC API device-response test', () => {
  let agent: Agent

  beforeAll(async () => {
    agent = new Agent(getAgentOptions('mdoc-dcapi-test-agent', {}))
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  test('end-to-end: createDcApiRequest → createEncryptedDcApiDeviceResponse → verifyEncryptedDcApiDeviceResponse', async () => {
    const holderKey = await agent.kms.createKey({
      type: {
        kty: 'EC',
        crv: 'P-256',
      },
    })
    const issuerKey = await agent.kms.createKey({
      type: {
        kty: 'EC',
        crv: 'P-256',
      },
    })

    const currentDate = new Date()
    currentDate.setDate(currentDate.getDate() - 1)
    const nextDay = new Date(currentDate)
    nextDay.setDate(currentDate.getDate() + 2)

    const certificate = await X509Service.createCertificate(agent.context, {
      issuer: 'C=US,CN=credo',
      authorityKey: PublicJwk.fromPublicJwk(issuerKey.publicJwk),
      validity: {
        notBefore: currentDate,
        notAfter: nextDay,
      },
    })

    const mdoc = await Mdoc.sign(agent.context, {
      docType: 'org.iso.18013.5.1.mDL',
      holderKey: PublicJwk.fromPublicJwk(holderKey.publicJwk),
      issuerCertificate: certificate,
      namespaces: {
        'org.iso.18013.5.1': {
          family_name: 'Jones',
          given_name: 'Ava',
          birth_date: '2007-03-25',
          issue_date: '2023-09-01',
          expiry_date: '2028-09-31',
          issuing_country: 'US',
          issuing_authority: 'NY DMV',
          document_number: '01-856-5050',
        },
      },
    })

    // 2. Reader: import P-256 ECDH key pair + generate nonce → createDcApiRequest
    const importedReaderKey = await agent.kms.importKey({
      privateJwk: READER_PRIVATE_JWK_P256,
    })
    const readerPublicJwk = PublicJwk.fromPublicJwk(importedReaderKey.publicJwk)

    const nonce = new Uint8Array(16).fill(42) // deterministic for testing

    const documentRequests = [
      {
        docType: 'org.iso.18013.5.1.mDL',
        nameSpaces: {
          'org.iso.18013.5.1': {
            family_name: true,
            given_name: true,
            birth_date: true,
            issue_date: true,
          },
        },
        readerAuth: {
          readerKey: PublicJwk.fromPublicJwk(issuerKey.publicJwk),
          x5chain: [certificate.toString('pem')],
        },
      },
    ]

    const dcApiRequest = await MdocDeviceResponse.createDcApiRequest(agent.context, {
      documentRequests,
      nonce,
      recipientPublicJwk: readerPublicJwk,
    })

    expect(dcApiRequest.deviceRequest).toBeDefined()
    expect(dcApiRequest.encryptionInfo).toBeDefined()
    expect(typeof dcApiRequest.deviceRequest).toBe('string')
    expect(typeof dcApiRequest.encryptionInfo).toBe('string')

    // 3. Holder: createEncryptedDcApiDeviceResponse
    const origin = 'https://example.com'

    const encryptedResponse = await MdocDeviceResponse.createEncryptedDcApiDeviceResponse(agent.context, {
      mdocs: [mdoc],
      documentRequests,
      encryptionInfoBase64Url: dcApiRequest.encryptionInfo,
      origin,
    })

    expect(encryptedResponse.Response).toBeDefined()
    expect(typeof encryptedResponse.Response).toBe('string')

    // 4. Reader: verifyEncryptedDcApiDeviceResponse
    const verifiedDocs = await MdocDeviceResponse.verifyEncryptedDcApiDeviceResponse(agent.context, {
      encryptedResponse: encryptedResponse.Response,
      encryptionInfoBase64Url: dcApiRequest.encryptionInfo,
      origin,
      readerPrivateJwk: READER_PRIVATE_JWK_P256,
      trustedCertificates: [certificate.toString('pem')],
    })

    // 5. Assert returned documents
    expect(verifiedDocs).toHaveLength(1)
  })
})
