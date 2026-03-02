import { AgentContext } from '../../agent'
import { injectable } from '../../plugins'
import type { Query, QueryOptions } from '../../storage/StorageService'
import { Mdoc } from './Mdoc'
import type {
  MdocDcApiEncryptedDeviceResponse,
  MdocDcApiEncryptedDeviceResponseOptions,
  MdocDcApiRequest,
  MdocDcApiRequestOptions,
  MdocDcApiVerifyOptions,
  MdocSignOptions,
  MdocStoreOptions,
  MdocVerifyOptions,
} from './MdocOptions'
import { MdocService } from './MdocService'
import type { MdocRecord } from './repository'

/**
 * @public
 */
@injectable()
export class MdocApi {
  private agentContext: AgentContext
  private mdocService: MdocService

  public constructor(agentContext: AgentContext, mdocService: MdocService) {
    this.agentContext = agentContext
    this.mdocService = mdocService
  }

  /**
   * Create a new Mdoc, with a spcific doctype, namespace, and validity info.
   *
   * @param options {MdocSignOptions}
   * @returns {Promise<Mdoc>}
   */
  public async sign(options: MdocSignOptions) {
    return await this.mdocService.signMdoc(this.agentContext, options)
  }

  /**
   *
   * Verify an incoming mdoc. It will check whether everything is valid, but also returns parts of the validation.
   *
   * For example, you might still want to continue with a flow if not all the claims are included, but the signature is valid.
   *
   */
  public async verify(mdoc: Mdoc, options: MdocVerifyOptions) {
    return await this.mdocService.verifyMdoc(this.agentContext, mdoc, options)
  }

  /**
   * Create a Mdoc class from a base64url encoded Mdoc Issuer-Signed structure
   */
  public fromBase64Url(base64Url: string) {
    return Mdoc.fromBase64Url(base64Url)
  }

  public async store(options: MdocStoreOptions) {
    return await this.mdocService.store(this.agentContext, options)
  }

  public async getById(id: string): Promise<MdocRecord> {
    return await this.mdocService.getById(this.agentContext, id)
  }

  public async getAll(): Promise<Array<MdocRecord>> {
    return await this.mdocService.getAll(this.agentContext)
  }

  public async findAllByQuery(query: Query<MdocRecord>, queryOptions?: QueryOptions): Promise<Array<MdocRecord>> {
    return await this.mdocService.findByQuery(this.agentContext, query, queryOptions)
  }

  public async deleteById(id: string) {
    return await this.mdocService.deleteById(this.agentContext, id)
  }

  public async update(mdocRecord: MdocRecord) {
    return await this.mdocService.update(this.agentContext, mdocRecord)
  }

  public async createDcApiRequest(options: MdocDcApiRequestOptions): Promise<MdocDcApiRequest> {
    return this.mdocService.createDcApiRequest(this.agentContext, options)
  }

  public async createEncryptedDcApiDeviceResponse(
    options: MdocDcApiEncryptedDeviceResponseOptions
  ): Promise<MdocDcApiEncryptedDeviceResponse> {
    return this.mdocService.createEncryptedDcApiDeviceResponse(this.agentContext, options)
  }

  public async verifyEncryptedDcApiDeviceResponse(options: MdocDcApiVerifyOptions): Promise<Mdoc[]> {
    return this.mdocService.verifyEncryptedDcApiDeviceResponse(this.agentContext, options)
  }
}
