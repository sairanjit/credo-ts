import { AgentContext } from '../../agent'
import { injectable } from '../../plugins'
import type { Query, QueryOptions } from '../../storage/StorageService'
import { Mdoc } from './Mdoc'
import { parseDcApiDeviceRequest } from './MdocDcApiRequest'
import { MdocDeviceResponse } from './MdocDeviceResponse'
import type {
  MdocDcApiRequestResolution,
  MdocDcApiResolveOptions,
  MdocDcApiEncryptedDeviceResponse,
  MdocDcApiEncryptedDeviceResponseOptions,
  MdocDcApiRequest,
  MdocDcApiRequestOptions,
  MdocDcApiVerifyOptions,
  MdocDeviceResponseOptions,
  MdocDeviceResponsePresentationDefinitionOptions,
  MdocDeviceResponseVerifyOptions,
  MdocSignOptions,
  MdocStoreOptions,
  MdocVerifyOptions,
} from './MdocOptions'
import { MdocRecord, MdocRepository } from './repository'

const getMissingRequestedNameSpaces = (
  available: Record<string, Record<string, unknown>>,
  requested: Record<string, Record<string, boolean>>
): Record<string, string[]> => {
  const missing: Record<string, string[]> = {}

  for (const [namespace, requestedElements] of Object.entries(requested)) {
    const availableElements = available[namespace]
    const requestedKeys = Object.keys(requestedElements ?? {})

    if (!availableElements) {
      if (requestedKeys.length > 0) missing[namespace] = requestedKeys
      continue
    }

    const missingKeys = requestedKeys.filter((key) => !(key in availableElements))
    if (missingKeys.length > 0) missing[namespace] = missingKeys
  }

  return missing
}

/**
 * @internal
 */
@injectable()
export class MdocService {
  private MdocRepository: MdocRepository

  public constructor(mdocRepository: MdocRepository) {
    this.MdocRepository = mdocRepository
  }

  public mdocFromBase64Url(hexEncodedMdoc: string) {
    return Mdoc.fromBase64Url(hexEncodedMdoc)
  }

  public signMdoc(agentContext: AgentContext, options: MdocSignOptions) {
    return Mdoc.sign(agentContext, options)
  }

  public async verifyMdoc(agentContext: AgentContext, mdoc: Mdoc, options: MdocVerifyOptions) {
    return await mdoc.verify(agentContext, options)
  }

  public async createDeviceResponse(agentContext: AgentContext, options: MdocDeviceResponseOptions) {
    return MdocDeviceResponse.createDeviceResponse(agentContext, options)
  }

  public async createPresentationDefinitionDeviceResponse(
    agentContext: AgentContext,
    options: MdocDeviceResponsePresentationDefinitionOptions
  ) {
    return MdocDeviceResponse.createPresentationDefinitionDeviceResponse(agentContext, options)
  }

  public async verifyDeviceResponse(agentContext: AgentContext, options: MdocDeviceResponseVerifyOptions) {
    const deviceResponse = MdocDeviceResponse.fromBase64Url(options.deviceResponse)
    return deviceResponse.verify(agentContext, options)
  }

  public async createDcApiRequest(
    agentContext: AgentContext,
    options: MdocDcApiRequestOptions
  ): Promise<MdocDcApiRequest> {
    return MdocDeviceResponse.createDcApiRequest(agentContext, options)
  }

  public parseDcApiDeviceRequest(deviceRequestBase64Url: string) {
    return parseDcApiDeviceRequest(deviceRequestBase64Url)
  }

  public async resolveDcApiRequest(
    agentContext: AgentContext,
    options: MdocDcApiResolveOptions
  ): Promise<MdocDcApiRequestResolution> {
    const { deviceRequest, requireAllNamespaces = true } = options
    const parsedRequest = parseDcApiDeviceRequest(deviceRequest)

    const uniqueDocTypes = Array.from(new Set(parsedRequest.documentRequests.map((request) => request.docType)))

    const records =
      uniqueDocTypes.length === 0
        ? []
        : await this.findByQuery(agentContext, {
            $or: uniqueDocTypes.map((docType) => ({
              docType,
            })),
          })

    const recordsByDocType = new Map<string, MdocRecord[]>()
    for (const record of records) {
      const docType = record.getTags().docType
      const existing = recordsByDocType.get(docType)
      if (existing) existing.push(record)
      else recordsByDocType.set(docType, [record])
    }

    const matches = parsedRequest.documentRequests.map((documentRequest) => {
      const candidates = recordsByDocType.get(documentRequest.docType) ?? []

      const matchingRecords = requireAllNamespaces
        ? candidates.filter((record) => {
            const mdoc = record.firstCredential
            const missing = getMissingRequestedNameSpaces(mdoc.issuerSignedNamespaces, documentRequest.nameSpaces)
            return Object.keys(missing).length === 0
          })
        : candidates

      return {
        documentRequest,
        matchingRecords,
      }
    })

    return {
      parsedRequest,
      matches,
    }
  }

  public async createEncryptedDcApiDeviceResponse(
    agentContext: AgentContext,
    options: MdocDcApiEncryptedDeviceResponseOptions
  ): Promise<MdocDcApiEncryptedDeviceResponse> {
    return MdocDeviceResponse.createEncryptedDcApiDeviceResponse(agentContext, options)
  }

  public async verifyEncryptedDcApiDeviceResponse(
    agentContext: AgentContext,
    options: MdocDcApiVerifyOptions
  ): Promise<Mdoc[]> {
    return MdocDeviceResponse.verifyEncryptedDcApiDeviceResponse(agentContext, options)
  }

  public async store(agentContext: AgentContext, options: MdocStoreOptions) {
    await this.MdocRepository.save(agentContext, options.record)

    return options.record
  }

  public async getById(agentContext: AgentContext, id: string): Promise<MdocRecord> {
    return await this.MdocRepository.getById(agentContext, id)
  }

  public async getAll(agentContext: AgentContext): Promise<Array<MdocRecord>> {
    return await this.MdocRepository.getAll(agentContext)
  }

  public async findByQuery(
    agentContext: AgentContext,
    query: Query<MdocRecord>,
    queryOptions?: QueryOptions
  ): Promise<Array<MdocRecord>> {
    return await this.MdocRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async deleteById(agentContext: AgentContext, id: string) {
    await this.MdocRepository.deleteById(agentContext, id)
  }

  public async update(agentContext: AgentContext, mdocRecord: MdocRecord) {
    await this.MdocRepository.update(agentContext, mdocRecord)
  }
}
