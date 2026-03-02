import type { MdocContext, PresentationDefinition, ReaderAuth } from '@animo-id/mdoc'
import {
  cborEncode,
  DataItem,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedDocument,
  MDoc,
  MDocStatus,
  limitDisclosureToInputDescriptor as mdocLimitDisclosureToInputDescriptor,
  defaultCallback as onCheck,
  parseDeviceResponse,
  parseIssuerSigned,
  Verifier,
} from '@animo-id/mdoc'
import type { InputDescriptorV2 } from '@sphereon/pex-models'
import { Kms } from '../..'
import type { AgentContext } from '../../agent'
import { TypedArrayEncoder } from './../../utils'
import { uuid } from '../../utils/uuid'
import type { DifPresentationExchangeDefinition } from '../dif-presentation-exchange'
import type { KnownJwaSignatureAlgorithm } from '../kms'
import { PublicJwk } from '../kms'
import { ClaimFormat } from '../vc'
import { X509Certificate } from '../x509'
import { Mdoc } from './Mdoc'
import { getMdocContext } from './MdocContext'
import {
  buildEncryptedResponseBase64Url,
  createEncryptionInfoBase64Url,
  hpkeDecrypt,
  hpkeEncrypt,
  parseEncryptedResponse,
  parseEncryptionInfo,
} from './MdocDcApiUtils'
import { MdocError } from './MdocError'
import type {
  MdocDcApiEncryptedDeviceResponse,
  MdocDcApiEncryptedDeviceResponseOptions,
  MdocDcApiRequest,
  MdocDcApiRequestOptions,
  MdocDcApiVerifyOptions,
  MdocDeviceResponseOptions,
  MdocDeviceResponsePresentationDefinitionOptions,
  MdocDeviceResponseVerifyOptions,
  MdocDocumentRequestReaderAuth,
  MdocSessionTranscriptOptions,
} from './MdocOptions'
import { isMdocSupportedSignatureAlgorithm, mdocSupportedSignatureAlgorithms } from './mdocSupportedAlgs'
import { nameSpacesRecordToMap } from './mdocUtil'

export class MdocDeviceResponse {
  private constructor(
    public base64Url: string,
    public documents: Mdoc[]
  ) {}

  /**
   * claim format is convenience method added to all credential instances
   */
  public get claimFormat() {
    return ClaimFormat.MsoMdoc as const
  }

  /**
   * Encoded is convenience method added to all credential instances
   */
  public get encoded() {
    return this.base64Url
  }

  /**
   * To support a single DeviceResponse with multiple documents in OpenID4VP
   */
  public splitIntoSingleDocumentResponses(): MdocDeviceResponse[] {
    const deviceResponses: MdocDeviceResponse[] = []

    if (this.documents.length === 0) {
      throw new MdocError('mdoc device response does not contain any mdocs')
    }

    for (const document of this.documents) {
      const deviceResponse = new MDoc()

      deviceResponse.addDocument(document.issuerSignedDocument)

      deviceResponses.push(MdocDeviceResponse.fromDeviceResponse(deviceResponse))
    }

    return deviceResponses
  }

  private static fromDeviceResponse(mdoc: MDoc) {
    const documents = mdoc.documents.map((doc) => {
      const prepared = doc.prepare()
      const docType = prepared.get('docType') as string
      const issuerSigned = cborEncode(prepared.get('issuerSigned'))
      const deviceSigned = cborEncode(prepared.get('deviceSigned'))

      return Mdoc.fromDeviceSignedDocument(
        TypedArrayEncoder.toBase64URL(issuerSigned),
        TypedArrayEncoder.toBase64URL(deviceSigned),
        docType
      )
    })

    return new MdocDeviceResponse(TypedArrayEncoder.toBase64URL(mdoc.encode()), documents)
  }

  public static fromBase64Url(base64Url: string) {
    const parsed = parseDeviceResponse(TypedArrayEncoder.fromBase64(base64Url))
    if (parsed.status !== MDocStatus.OK) {
      throw new MdocError('Parsing Mdoc Device Response failed.')
    }

    return MdocDeviceResponse.fromDeviceResponse(parsed)
  }

  private static assertMdocInputDescriptor(inputDescriptor: InputDescriptorV2) {
    if (!inputDescriptor.format || !inputDescriptor.format.mso_mdoc) {
      throw new MdocError(`Input descriptor must contain 'mso_mdoc' format property`)
    }

    if (!inputDescriptor.format.mso_mdoc.alg) {
      throw new MdocError(`Input descriptor mso_mdoc must contain 'alg' property`)
    }

    if (!inputDescriptor.constraints?.limit_disclosure || inputDescriptor.constraints.limit_disclosure !== 'required') {
      throw new MdocError(
        `Input descriptor must contain 'limit_disclosure' constraints property which is set to required`
      )
    }

    if (!inputDescriptor.constraints?.fields?.every((field) => field.intent_to_retain !== undefined)) {
      throw new MdocError(`Input descriptor must contain 'intent_to_retain' constraints property`)
    }

    return {
      ...inputDescriptor,
      format: {
        mso_mdoc: inputDescriptor.format.mso_mdoc,
      },
      constraints: {
        ...inputDescriptor.constraints,
        limit_disclosure: 'required',
        fields: (inputDescriptor.constraints.fields ?? []).map((field) => {
          return {
            ...field,
            intent_to_retain: field.intent_to_retain ?? false,
          }
        }),
      },
    } satisfies PresentationDefinition['input_descriptors'][number]
  }

  public static partitionPresentationDefinition = (pd: DifPresentationExchangeDefinition) => {
    const nonMdocPresentationDefinition: DifPresentationExchangeDefinition = {
      ...pd,
      input_descriptors: pd.input_descriptors.filter(
        (id) => !Object.keys((id as InputDescriptorV2).format ?? {}).includes('mso_mdoc')
      ),
    } as DifPresentationExchangeDefinition

    const mdocPresentationDefinition = {
      ...pd,
      format: { mso_mdoc: pd.format?.mso_mdoc },
      input_descriptors: (pd.input_descriptors as InputDescriptorV2[])
        .filter((id) => Object.keys(id.format ?? {}).includes('mso_mdoc'))
        .map(this.assertMdocInputDescriptor),
    }

    return { mdocPresentationDefinition, nonMdocPresentationDefinition }
  }

  private static createPresentationSubmission(input: {
    id: string
    presentationDefinition: {
      id: string
      input_descriptors: ReturnType<typeof MdocDeviceResponse.assertMdocInputDescriptor>[]
    }
  }) {
    const { id, presentationDefinition } = input
    if (presentationDefinition.input_descriptors.length !== 1) {
      throw new MdocError('Currently Mdoc Presentation Submissions can only be created for a sigle input descriptor')
    }
    return {
      id,
      definition_id: presentationDefinition.id,
      descriptor_map: [
        {
          id: presentationDefinition.input_descriptors[0].id,
          format: 'mso_mdoc',
          path: '$',
        },
      ],
    }
  }

  public static limitDisclosureToInputDescriptor(options: { inputDescriptor: InputDescriptorV2; mdoc: Mdoc }) {
    const { mdoc } = options

    const inputDescriptor = MdocDeviceResponse.assertMdocInputDescriptor(options.inputDescriptor)
    const _mdoc = parseIssuerSigned(TypedArrayEncoder.fromBase64(mdoc.base64Url), mdoc.docType)

    const disclosure = mdocLimitDisclosureToInputDescriptor(_mdoc, inputDescriptor)
    const disclosedPayloadAsRecord = Object.fromEntries(
      Array.from(disclosure.entries()).map(([namespace, issuerSignedItem]) => {
        return [
          namespace,
          Object.fromEntries(issuerSignedItem.map((item) => [item.elementIdentifier, item.elementValue])),
        ]
      })
    )

    return disclosedPayloadAsRecord
  }

  public static async createPresentationDefinitionDeviceResponse(
    agentContext: AgentContext,
    options: MdocDeviceResponsePresentationDefinitionOptions
  ) {
    const presentationDefinition = MdocDeviceResponse.partitionPresentationDefinition(
      options.presentationDefinition
    ).mdocPresentationDefinition

    const docTypes = options.mdocs.map((i) => i.docType)

    const combinedDeviceResponseMdoc = new MDoc()

    for (const document of options.mdocs) {
      const deviceKeyJwk = document.deviceKey
      if (!deviceKeyJwk) throw new MdocError(`Device key is missing in mdoc with doctype ${document.docType}`)

      // Set keyId to legacy key id if it doesn't have a key id set
      if (!deviceKeyJwk.hasKeyId) {
        deviceKeyJwk.keyId = deviceKeyJwk.legacyKeyId
      }

      const alg = MdocDeviceResponse.getAlgForDeviceKeyJwk(deviceKeyJwk)

      // We do PEX filtering on a different layer, so we only include the needed input descriptor here
      const presentationDefinitionForDocument = {
        ...presentationDefinition,
        input_descriptors: presentationDefinition.input_descriptors.filter(
          (inputDescriptor) => inputDescriptor.id === document.docType
        ),
      }

      const mdocContext = getMdocContext(agentContext)
      const issuerSignedDocument = parseIssuerSigned(TypedArrayEncoder.fromBase64(document.base64Url), document.docType)
      const deviceResponseBuilder = DeviceResponse.from(new MDoc([issuerSignedDocument]))
        .usingPresentationDefinition(presentationDefinitionForDocument)
        .authenticateWithSignature(deviceKeyJwk.toJson(), alg)
        .usingSessionTranscriptBytes(
          await MdocDeviceResponse.getSessionTranscriptBytesForOptions(mdocContext, options.sessionTranscriptOptions)
        )

      for (const [nameSpace, nameSpaceValue] of Object.entries(options.deviceNameSpaces ?? {})) {
        deviceResponseBuilder.addDeviceNameSpace(nameSpace, nameSpaceValue)
      }

      const deviceResponseMdoc = await deviceResponseBuilder.sign(mdocContext)
      combinedDeviceResponseMdoc.addDocument(deviceResponseMdoc.documents[0])
    }

    return {
      deviceResponseBase64Url: TypedArrayEncoder.toBase64URL(combinedDeviceResponseMdoc.encode()),
      presentationSubmission: MdocDeviceResponse.createPresentationSubmission({
        id: `MdocPresentationSubmission ${uuid()}`,
        presentationDefinition: {
          ...presentationDefinition,
          input_descriptors: presentationDefinition.input_descriptors.filter((i) => docTypes.includes(i.id)),
        },
      }),
    }
  }

  public static async createDeviceResponse(agentContext: AgentContext, options: MdocDeviceResponseOptions) {
    const combinedDeviceResponseMdoc = new MDoc()

    for (const document of options.mdocs) {
      const deviceKeyJwk = document.deviceKey
      if (!deviceKeyJwk) throw new MdocError(`Device key is missing in mdoc with doctype ${document.docType}`)
      const alg = MdocDeviceResponse.getAlgForDeviceKeyJwk(deviceKeyJwk)

      // Set keyId to legacy key id if it doesn't have a key id set
      if (!deviceKeyJwk.hasKeyId) {
        deviceKeyJwk.keyId = deviceKeyJwk.legacyKeyId
      }

      const issuerSignedDocument = parseIssuerSigned(TypedArrayEncoder.fromBase64(document.base64Url), document.docType)

      const deviceRequestForDocument = DeviceRequest.from(
        '1.0',
        options.documentRequests
          .filter((request) => request.docType === issuerSignedDocument.docType)
          .map((request) => ({
            itemsRequestData: {
              docType: request.docType,
              nameSpaces: nameSpacesRecordToMap(request.nameSpaces),
            },
          }))
      )

      const mdocContext = getMdocContext(agentContext)
      const deviceResponseBuilder = DeviceResponse.from(new MDoc([issuerSignedDocument]))
        .authenticateWithSignature(deviceKeyJwk.toJson(), alg)
        .usingDeviceRequest(deviceRequestForDocument)
        .usingSessionTranscriptBytes(
          await MdocDeviceResponse.getSessionTranscriptBytesForOptions(mdocContext, options.sessionTranscriptOptions)
        )

      for (const [nameSpace, nameSpaceValue] of Object.entries(options.deviceNameSpaces ?? {})) {
        deviceResponseBuilder.addDeviceNameSpace(nameSpace, nameSpaceValue)
      }

      const deviceResponseMdoc = await deviceResponseBuilder.sign(mdocContext)
      combinedDeviceResponseMdoc.addDocument(deviceResponseMdoc.documents[0])
    }

    return combinedDeviceResponseMdoc.encode()
  }

  public async verify(agentContext: AgentContext, options: Omit<MdocDeviceResponseVerifyOptions, 'deviceResponse'>) {
    const verifier = new Verifier()
    const mdocContext = getMdocContext(agentContext)

    onCheck({
      status: this.documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must include at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    const deviceResponse = parseDeviceResponse(TypedArrayEncoder.fromBase64(this.base64Url))

    // NOTE: we do not use the verification from mdoc library, as it checks all documents
    // based on the same trusted certificates
    for (const documentIndex of this.documents.keys()) {
      const rawDocument = deviceResponse.documents[documentIndex]
      const document = this.documents[documentIndex]

      const verificationResult = await document.verify(agentContext, {
        now: options.now,
        trustedCertificates: options.trustedCertificates,
      })

      if (!verificationResult.isValid) {
        throw new MdocError(`Mdoc at index ${documentIndex} is not valid. ${verificationResult.error}`)
      }

      if (!(rawDocument instanceof DeviceSignedDocument)) {
        onCheck({
          status: 'FAILED',
          category: 'DEVICE_AUTH',
          check: `The document is not signed by the device. ${document.docType}`,
        })
        continue
      }

      await verifier.verifyDeviceSignature(
        {
          sessionTranscriptBytes: await MdocDeviceResponse.getSessionTranscriptBytesForOptions(
            mdocContext,
            options.sessionTranscriptOptions
          ),
          deviceSigned: rawDocument,
        },
        mdocContext
      )
    }

    if (deviceResponse.documentErrors.length > 1) {
      throw new MdocError('Device response verification failed.')
    }

    if (deviceResponse.status !== MDocStatus.OK) {
      throw new MdocError('Device response verification failed. An unknown error occurred.')
    }

    return this.documents
  }

  /**
   * Create a DC API DeviceRequest (version 1.1) + EncryptionInfo, both as base64url.
   *
   * The DeviceRequest CBOR map includes:
   *   - version: "1.1"
   *   - docRequests: per-document itemsRequest + optional per-doc readerAuth
   *   - deviceRequestInfo: DataItem with useCases describing which docs are mandatory
   *   - readerAuthAll: (when any readerAuth is provided) a COSE_Sign1 over all ItemsRequests combined
   */
  public static async createDcApiRequest(
    agentContext: AgentContext,
    options: MdocDcApiRequestOptions
  ): Promise<MdocDcApiRequest> {
    // Step 1: Build per-document ItemsRequest DataItems explicitly.
    // This avoids DeviceRequest.from(), which adds `requestInfo: undefined`.
    const docEntries = await Promise.all(
      options.documentRequests.map(async (request) => {
        const itemsRequestDataItem = DataItem.fromData({
          docType: request.docType,
          nameSpaces: nameSpacesRecordToMap(request.nameSpaces),
        })
        const itemsRequestPayloadBytes = cborEncode(itemsRequestDataItem)

        const readerAuth = request.readerAuth
          ? await MdocDeviceResponse.buildReaderAuth(agentContext, itemsRequestPayloadBytes, request.readerAuth)
          : undefined

        return { itemsRequestDataItem, readerAuth }
      })
    )

    // Step 2: Encode each DocRequest as a CBOR map {itemsRequest, readerAuth?}
    const docRequestMaps = docEntries.map(({ itemsRequestDataItem, readerAuth }) => {
      const docRequestMap = new Map<string, unknown>([['itemsRequest', itemsRequestDataItem]])
      if (readerAuth) docRequestMap.set('readerAuth', readerAuth)
      return docRequestMap
    })

    // Step 3: Build deviceRequestInfo — one mandatory use case covering all document indices
    const docIndices = docEntries.map((_, i) => i)
    const deviceRequestInfo = DataItem.fromData({
      useCases: [{ mandatory: true, documentSets: [docIndices] }],
    })

    // Step 4: Build readerAuthAll when any doc request carries readerAuth.
    // readerAuthAll signs a CBOR array of all ItemsRequest DataItems combined.
    const firstReaderAuthOptions = options.documentRequests.find((r) => r.readerAuth)?.readerAuth
    let readerAuthAll: ReaderAuth[] | undefined
    if (firstReaderAuthOptions) {
      const allItemsPayload = cborEncode(docEntries.map((e) => e.itemsRequestDataItem))
      const readerAuthAllEntry = await MdocDeviceResponse.buildReaderAuth(
        agentContext,
        allItemsPayload,
        firstReaderAuthOptions
      )
      readerAuthAll = [readerAuthAllEntry]
    }

    // Step 5: Assemble the DeviceRequest CBOR map
    const deviceRequestMap = new Map<string, unknown>([
      ['version', '1.1'],
      ['docRequests', docRequestMaps],
      ['deviceRequestInfo', deviceRequestInfo],
    ])
    if (readerAuthAll) {
      deviceRequestMap.set('readerAuthAll', readerAuthAll)
    }

    const encryptionInfo = createEncryptionInfoBase64Url({
      nonce: options.nonce,
      recipientPublicJwk: options.recipientPublicJwk,
    })

    return {
      deviceRequest: TypedArrayEncoder.toBase64URL(cborEncode(deviceRequestMap)),
      encryptionInfo,
    }
  }

  /**
   * Build a COSE_Sign1 ReaderAuth tuple.
   * Protected: {1: coseAlg}  Unprotected: {33: x5chain}  Payload: detached (null in structure).
   * The actual payload bytes are used only for the Sig_Structure during signing.
   */
  private static async buildReaderAuth(
    agentContext: AgentContext,
    payloadBytes: Uint8Array,
    readerAuthOptions: MdocDocumentRequestReaderAuth
  ): Promise<ReaderAuth> {
    const readerKey = readerAuthOptions.readerKey

    const jwsAlgorithm = readerKey.supportedSignatureAlgorithms.find(isMdocSupportedSignatureAlgorithm)
    if (!jwsAlgorithm) {
      throw new MdocError(
        `Reader key does not support any mdoc-compatible signature algorithm. Supported: ${readerKey.supportedSignatureAlgorithms.join(', ')}`
      )
    }

    const coseAlgMapping: Record<string, number> = { ES256: -7, ES384: -35, ES512: -36, EdDSA: -8 }
    const coseAlg = coseAlgMapping[jwsAlgorithm]
    if (coseAlg === undefined) {
      throw new MdocError(`No COSE algorithm mapping for ${jwsAlgorithm}`)
    }

    const protectedHeadersBytes = cborEncode(new Map([[1, coseAlg]]))
    const certDerBytesArray = readerAuthOptions.x5chain.map(
      (cert) => X509Certificate.fromEncodedCertificate(cert).rawCertificate
    )
    const unprotectedHeaders = new Map([[33, certDerBytesArray]])

    // Sig_Structure = ["Signature1", protected_bytes, external_aad, payload]
    const sigStructure = cborEncode(['Signature1', protectedHeadersBytes, new Uint8Array(0), payloadBytes])

    const kms = agentContext.resolve(Kms.KeyManagementApi)

    const { signature } = await kms.sign({
      data: sigStructure,
      algorithm: jwsAlgorithm as KnownJwaSignatureAlgorithm,
      keyId: readerKey.keyId,
    })

    // COSE_Sign1 with detached payload (null)
    return [protectedHeadersBytes, unprotectedHeaders, null, signature] as unknown as ReaderAuth
  }

  /**
   * Create an HPKE-encrypted DC API DeviceResponse.
   */
  public static async createEncryptedDcApiDeviceResponse(
    agentContext: AgentContext,
    options: MdocDcApiEncryptedDeviceResponseOptions
  ): Promise<MdocDcApiEncryptedDeviceResponse> {
    const sessionTranscriptOptions = {
      type: 'dcapi' as const,
      encryptionInfoBase64Url: options.encryptionInfoBase64Url,
      origin: options.origin,
    }

    const deviceResponseBytes = await MdocDeviceResponse.createDeviceResponse(agentContext, {
      mdocs: options.mdocs,
      documentRequests: options.documentRequests,
      deviceNameSpaces: options.deviceNameSpaces,
      sessionTranscriptOptions,
    })

    const mdocContext = getMdocContext(agentContext)
    const sessionTranscriptBytes = await MdocDeviceResponse.getSessionTranscriptBytesForOptions(
      mdocContext,
      sessionTranscriptOptions
    )

    const { recipientPublicKeyRawBytes } = parseEncryptionInfo(options.encryptionInfoBase64Url)

    // For dcapi, HPKE info = plain CBOR [null,null,["dcapi",hash]] — no DataItem/tag-24 wrapper.
    // Wallet uses Cbor.encode(sessionTranscript) which is plain, so we compute it directly here.
    let hpkeInfoEncrypt: Uint8Array
    if (sessionTranscriptOptions.type === 'dcapi') {
      const hi = cborEncode([sessionTranscriptOptions.encryptionInfoBase64Url, sessionTranscriptOptions.origin])
      const hh = await getMdocContext(agentContext).crypto.digest({ digestAlgorithm: 'SHA-256', bytes: hi })
      hpkeInfoEncrypt = cborEncode([null, null, ['dcapi', hh]])
    } else {
      hpkeInfoEncrypt = sessionTranscriptBytes
    }

    const { enc, cipherText } = await hpkeEncrypt({
      recipientPublicKeyBytes: recipientPublicKeyRawBytes,
      info: hpkeInfoEncrypt,
      plaintext: deviceResponseBytes,
    })

    return {
      Response: buildEncryptedResponseBase64Url(enc, cipherText),
    }
  }

  /**
   * Verify an HPKE-encrypted DC API DeviceResponse.
   */
  public static async verifyEncryptedDcApiDeviceResponse(
    agentContext: AgentContext,
    options: MdocDcApiVerifyOptions
  ): Promise<Mdoc[]> {
    const { enc, cipherText } = parseEncryptedResponse(options.encryptedResponse)

    const sessionTranscriptOptions = {
      type: 'dcapi' as const,
      encryptionInfoBase64Url: options.encryptionInfoBase64Url,
      origin: options.origin,
    }

    const mdocContext = getMdocContext(agentContext)
    const sessionTranscriptBytes = await MdocDeviceResponse.getSessionTranscriptBytesForOptions(
      mdocContext,
      sessionTranscriptOptions
    )

    // HPKE info must be plain CBOR (no tag-24). sessionTranscriptBytes is DataItem/tag-24 wrapped;
    // .buffer gives the inner plain CBOR bytes matching wallet's Cbor.encode(sessionTranscript)
    const hpkeInfo = (sessionTranscriptBytes as unknown as { buffer: Uint8Array }).buffer ?? sessionTranscriptBytes

    const deviceResponseBytes = await hpkeDecrypt({
      recipientPrivateJwk: options.readerPrivateJwk,
      enc,
      info: hpkeInfo,
      cipherText,
    })

    const deviceResponse = MdocDeviceResponse.fromBase64Url(TypedArrayEncoder.toBase64URL(deviceResponseBytes))

    return deviceResponse.verify(agentContext, {
      sessionTranscriptOptions,
      trustedCertificates: options.trustedCertificates,
      now: options.now,
    })
  }

  private static async getSessionTranscriptBytesForOptions(
    context: MdocContext,
    options: MdocSessionTranscriptOptions
  ) {
    if (options.type === 'sesionTranscriptBytes') {
      return options.sessionTranscriptBytes
    }

    // NOTE: temporary until we have updated to the new major version of mdoc
    // Based on https://github.com/animo/mdoc/blob/main/src/mdoc/models/session-transcript.ts#L84
    if (options.type === 'openId4Vp') {
      return cborEncode(
        DataItem.fromData([
          null,
          null,
          [
            'OpenID4VPHandover',
            await context.crypto.digest({
              digestAlgorithm: 'SHA-256',
              bytes: cborEncode([
                options.clientId,
                options.verifierGeneratedNonce,
                options.encryptionJwk?.getJwkThumbprint('sha-256') ?? null,
                options.responseUri,
              ]),
            }),
          ],
        ])
      )
    }

    if (options.type === 'openId4VpDraft18') {
      return await DeviceResponse.calculateSessionTranscriptBytesForOID4VP({
        ...options,
        context,
      })
    }

    // NOTE: temporary until we have updated to the new major version of mdoc
    // Based on https://github.com/animo/mdoc/blob/main/src/mdoc/models/session-transcript.ts#L65
    if (options.type === 'openId4VpDcApi') {
      return cborEncode(
        DataItem.fromData([
          null,
          null,
          [
            'OpenID4VPDCAPIHandover',
            await context.crypto.digest({
              digestAlgorithm: 'SHA-256',
              bytes: cborEncode([
                options.origin,
                options.verifierGeneratedNonce,
                options.encryptionJwk?.getJwkThumbprint('sha-256') ?? null,
              ]),
            }),
          ],
        ])
      )
    }

    if (options.type === 'openId4VpDcApiDraft24') {
      return await DeviceResponse.calculateSessionTranscriptBytesForOID4VPDCApi({
        ...options,
        context,
      })
    }

    if (options.type === 'dcapi') {
      // Session transcript: [null, null, ["dcapi", SHA-256(CBOR([encryptionInfoBase64Url, origin]))]]
      // - encryptionInfoBase64Url is a tstr (the base64url string, not raw bytes)
      // - returned as DataItem/tag-24 so @animo-id/mdoc verifyDeviceSignature can do cborDecode(bytes).data
      // - HPKE callers must use cborDecode(sessionTranscriptBytes).buffer to get the plain inner CBOR
      const handoverInfoBytes = cborEncode([options.encryptionInfoBase64Url, options.origin])
      const handoverHash = await context.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: handoverInfoBytes,
      })
      return cborEncode(DataItem.fromData([null, null, ['dcapi', handoverHash]]))
    }

    throw new MdocError('Unsupported session transcript option')
  }

  private static getAlgForDeviceKeyJwk(jwk: PublicJwk) {
    const signatureAlgorithm = jwk.supportedSignatureAlgorithms.find(isMdocSupportedSignatureAlgorithm)
    if (!signatureAlgorithm) {
      throw new MdocError(
        `Unable to create mdoc device response. No supported signature algorithm found to sign device response for jwk  ${
          jwk.jwkTypeHumanDescription
        }. Key supports algs ${jwk.supportedSignatureAlgorithms.join(
          ', '
        )}. mdoc supports algs ${mdocSupportedSignatureAlgorithms.join(', ')}`
      )
    }

    return signatureAlgorithm
  }
}
