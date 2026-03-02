import { COSEKey, COSEKeyToRAW, cborDecode, cborEncode } from '@animo-id/mdoc'
import { AeadId, CipherSuite, KdfId, KemId } from 'hpke-js'
import type { JsonWebKey } from '../../crypto/webcrypto/types'
import { TypedArrayEncoder } from '../../utils'
import type { PublicJwk } from '../kms'

function createHpkeSuite() {
  return new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
}

/**
 * HPKE encrypt (holder side).
 * info = session transcript bytes (used as HPKE "info" parameter)
 */
export async function hpkeEncrypt(options: {
  recipientPublicKeyBytes: Uint8Array
  info: Uint8Array
  plaintext: Uint8Array
}): Promise<{ enc: Uint8Array; cipherText: Uint8Array }> {
  const suite = createHpkeSuite()
  const recipientPublicKey = await suite.kem.importKey('raw', options.recipientPublicKeyBytes, true)

  const sender = await suite.createSenderContext({
    recipientPublicKey,
    info: options.info,
  })

  const cipherTextBuffer = await sender.seal(options.plaintext)

  return {
    enc: new Uint8Array(sender.enc),
    cipherText: new Uint8Array(cipherTextBuffer),
  }
}

/**
 * HPKE decrypt (reader side).
 * info = session transcript bytes (used as HPKE "info" parameter)
 */
export async function hpkeDecrypt(options: {
  recipientPrivateJwk: JsonWebKey
  enc: Uint8Array
  info: Uint8Array
  cipherText: Uint8Array
}): Promise<Uint8Array> {
  const suite = createHpkeSuite()
  const recipientKey = await suite.kem.importKey('jwk', options.recipientPrivateJwk, false)

  const recipient = await suite.createRecipientContext({
    recipientKey,
    enc: options.enc,
    info: options.info,
  })

  const plaintext = await recipient.open(options.cipherText)
  return new Uint8Array(plaintext)
}

/**
 * Create the EncryptionInfo CBOR bytes encoded as base64url.
 * CBOR: ["dcapi", {nonce: Uint8Array, recipientPublicKey: COSE_Key}]
 */
export function createEncryptionInfoBase64Url(options: { nonce: Uint8Array; recipientPublicJwk: PublicJwk }): string {
  const coseKey = COSEKey.fromJWK(options.recipientPublicJwk.toJson({ includeKid: false }))
  // Decode the COSE key bytes back to a native Map so it is embedded as a COSE_Key map (not bstr)
  const coseKeyMap = cborDecode(coseKey.encode()) as Map<number, unknown>
  const encryptionInfoCbor = cborEncode(['dcapi', { nonce: options.nonce, recipientPublicKey: coseKeyMap }])
  return TypedArrayEncoder.toBase64URL(encryptionInfoCbor)
}

/**
 * Parse EncryptionInfo base64url → extract nonce + raw recipient public key bytes (uncompressed EC point)
 */
export function parseEncryptionInfo(encryptionInfoBase64Url: string): {
  nonce: Uint8Array
  recipientPublicKeyRawBytes: Uint8Array
} {
  const encryptionInfoBytes = TypedArrayEncoder.fromBase64(encryptionInfoBase64Url)
  // Decoded structure: ["dcapi", {nonce: Uint8Array, recipientPublicKey: COSE_Key map}]
  const decoded = cborDecode(encryptionInfoBytes) as unknown[]

  const innerMap = decoded[1] as Map<string, unknown>
  const nonce = innerMap.get('nonce') as Uint8Array
  const coseKeyMap = innerMap.get('recipientPublicKey') as Map<number, unknown>
  // Re-encode the COSE key map to bytes so COSEKeyToRAW can process it
  const rawBytes = COSEKeyToRAW(cborEncode(coseKeyMap))

  return { nonce, recipientPublicKeyRawBytes: rawBytes }
}

/**
 * Build the EncryptedResponse CBOR structure encoded as base64url.
 * CBOR: ["dcapi", {enc: Uint8Array, cipherText: Uint8Array}]
 */
export function buildEncryptedResponseBase64Url(enc: Uint8Array, cipherText: Uint8Array): string {
  const encryptedResponseCbor = cborEncode(['dcapi', { enc, cipherText }])
  return TypedArrayEncoder.toBase64URL(encryptedResponseCbor)
}

/**
 * Parse EncryptedResponse base64url → { enc, cipherText }
 */
export function parseEncryptedResponse(encryptedResponseBase64Url: string): {
  enc: Uint8Array
  cipherText: Uint8Array
} {
  const encryptedResponseBytes = TypedArrayEncoder.fromBase64(encryptedResponseBase64Url)
  // Decoded structure: ["dcapi", {enc: Uint8Array, cipherText: Uint8Array}]
  const decoded = cborDecode(encryptedResponseBytes) as unknown[]

  if (!Array.isArray(decoded) || decoded[0] !== 'dcapi') {
    throw new Error('Invalid EncryptedResponse: expected ["dcapi", {...}]')
  }

  const innerMap = decoded[1] as Map<string, Uint8Array>
  return { enc: innerMap.get('enc') as Uint8Array, cipherText: innerMap.get('cipherText') as Uint8Array }
}
