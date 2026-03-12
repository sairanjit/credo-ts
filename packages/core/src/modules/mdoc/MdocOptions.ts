import type { ReaderAuth, ValidityInfo } from '@animo-id/mdoc'
import type { JsonWebKey } from '../../crypto/webcrypto/types'
import type { AnyUint8Array } from '../../types'
import type { DifPresentationExchangeDefinition } from '../dif-presentation-exchange'
import { PublicJwk } from '../kms'
import type { EncodedX509Certificate, X509Certificate } from '../x509'
import { Mdoc } from './Mdoc'
import { MdocRecord } from './repository'

export { DateOnly } from '@animo-id/mdoc'

export type MdocNameSpaces = Record<string, Record<string, unknown>>

export interface MdocStoreOptions {
  record: MdocRecord
}

export type MdocVerifyOptions = {
  trustedCertificates?: EncodedX509Certificate[]
  now?: Date
}

export type MdocOpenId4VpSessionTranscriptOptions = {
  type: 'openId4Vp'
  responseUri: string
  clientId: string
  verifierGeneratedNonce: string
  encryptionJwk?: PublicJwk
}

export type MdocOpenId4VpDraft18SessionTranscriptOptions = {
  type: 'openId4VpDraft18'
  responseUri: string
  clientId: string
  verifierGeneratedNonce: string
  mdocGeneratedNonce: string
}

export type MdocSessionTranscriptByteOptions = {
  type: 'sesionTranscriptBytes'
  sessionTranscriptBytes: AnyUint8Array
}

export type MdocOpenId4VpDcApiSessionTranscriptOptions = {
  type: 'openId4VpDcApi'
  origin: string
  verifierGeneratedNonce: string
  encryptionJwk?: PublicJwk
}

export type MdocOpenId4VpDcApiDraft24SessionTranscriptOptions = {
  type: 'openId4VpDcApiDraft24'
  clientId: string
  origin: string
  verifierGeneratedNonce: string
}

export type MdocDcApiSessionTranscriptOptions = {
  type: 'dcapi'
  encryptionInfoBase64Url: string
  origin: string
}

export type MdocSessionTranscriptOptions =
  | MdocOpenId4VpSessionTranscriptOptions
  | MdocOpenId4VpDraft18SessionTranscriptOptions
  | MdocSessionTranscriptByteOptions
  | MdocOpenId4VpDcApiSessionTranscriptOptions
  | MdocOpenId4VpDcApiDraft24SessionTranscriptOptions
  | MdocDcApiSessionTranscriptOptions

export type MdocDocumentRequest = {
  docType: string
  nameSpaces: Record<string, Record<string, boolean>>
}

export type MdocDeviceResponseOptions = {
  mdocs: [Mdoc, ...Mdoc[]]
  documentRequests: MdocDocumentRequest[]
  deviceNameSpaces?: MdocNameSpaces
  sessionTranscriptOptions: MdocSessionTranscriptOptions
}

export type MdocDeviceResponsePresentationDefinitionOptions = {
  mdocs: [Mdoc, ...Mdoc[]]
  presentationDefinition: DifPresentationExchangeDefinition
  deviceNameSpaces?: MdocNameSpaces
  sessionTranscriptOptions: MdocSessionTranscriptOptions
}

export type MdocDeviceResponseVerifyOptions = {
  trustedCertificates?: EncodedX509Certificate[]
  sessionTranscriptOptions: MdocSessionTranscriptOptions
  /**
   * The base64Url-encoded device response string.
   */
  deviceResponse: string
  now?: Date
}

export type MdocDocumentRequestReaderAuth = {
  /**
   * The reader's signing key from the KMS. Must have a keyId set.
   */
  readerKey: PublicJwk
  /**
   * The certificate chain (PEM or base64) to include in the x5chain unprotected header.
   * The leaf certificate should be first.
   */
  x5chain: EncodedX509Certificate[]
}

export type MdocDcApiRequestOptions = {
  documentRequests: (MdocDocumentRequest & { readerAuth?: MdocDocumentRequestReaderAuth })[]
  nonce: Uint8Array
  recipientPublicJwk: PublicJwk
}

export type MdocDcApiRequest = {
  deviceRequest: string
  encryptionInfo: string
}

export type MdocDeviceRequestUseCase = {
  id?: string
  name?: string
  purpose?: string
  mandatory?: boolean
  documentSets?: number[][]
}

export type MdocDeviceRequestInfo = {
  useCases?: MdocDeviceRequestUseCase[]
} & Record<string, unknown>

export type MdocDcApiParsedDocumentRequest = MdocDocumentRequest & {
  readerAuth?: ReaderAuth
}

export type MdocDcApiParsedDeviceRequest = {
  version: string
  documentRequests: MdocDcApiParsedDocumentRequest[]
  deviceRequestInfo?: MdocDeviceRequestInfo
  readerAuthAll?: ReaderAuth[]
}

export type MdocDcApiResolveOptions = {
  /**
   * The base64url encoded DeviceRequest.
   */
  deviceRequest: string
  /**
   * If true (default), only return matches where all requested namespaces and data elements are present.
   */
  requireAllNamespaces?: boolean
}

export type MdocDcApiRequestMatch = {
  documentRequest: MdocDocumentRequest
  matchingRecords: MdocRecord[]
}

export type MdocDcApiRequestResolution = {
  parsedRequest: MdocDcApiParsedDeviceRequest
  matches: MdocDcApiRequestMatch[]
}

export type MdocDcApiEncryptedDeviceResponseOptions = {
  mdocs: [Mdoc, ...Mdoc[]]
  documentRequests: MdocDocumentRequest[]
  deviceNameSpaces?: MdocNameSpaces
  encryptionInfoBase64Url: string
  origin: string
}

export type MdocDcApiEncryptedDeviceResponse = {
  response: string
}

export type MdocDcApiVerifyOptions = {
  encryptedResponse: string
  encryptionInfoBase64Url: string
  origin: string
  readerPrivateJwk: JsonWebKey
  trustedCertificates?: EncodedX509Certificate[]
  now?: Date
}

export type MdocSignOptions = {
  docType: 'org.iso.18013.5.1.mDL' | (string & {})
  validityInfo?: Partial<ValidityInfo>
  namespaces: MdocNameSpaces

  /**
   *
   * The X509 certificate to use for signing the mDOC. The certificate MUST have a
   * publicJwk with key id configured, enabling signing with the KMS
   */
  issuerCertificate: X509Certificate
  holderKey: PublicJwk
}
