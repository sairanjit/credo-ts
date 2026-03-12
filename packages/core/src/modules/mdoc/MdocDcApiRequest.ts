import { cborDecode, DataItem } from '@animo-id/mdoc'
import type { ReaderAuth } from '@animo-id/mdoc'
import { TypedArrayEncoder } from '../../utils'
import { MdocError } from './MdocError'
import type {
  MdocDcApiParsedDeviceRequest,
  MdocDcApiParsedDocumentRequest,
  MdocDeviceRequestInfo,
  MdocDeviceRequestUseCase,
} from './MdocOptions'
import { namespacesMapToRecord } from './mdocUtil'

type MapLike = Map<string, unknown> | Record<string, unknown>

function getMapValue(mapLike: unknown, key: string): unknown {
  if (mapLike instanceof Map) return mapLike.get(key)
  if (mapLike && typeof mapLike === 'object' && !Array.isArray(mapLike)) {
    return (mapLike as Record<string, unknown>)[key]
  }

  return undefined
}

function unwrapDataItem(value: unknown): unknown {
  if (value instanceof DataItem) return value.data
  if (value && typeof value === 'object' && 'data' in value) return (value as { data: unknown }).data

  if (value instanceof Uint8Array) {
    try {
      const decoded = cborDecode(value)
      if (decoded instanceof DataItem) return decoded.data
      return decoded
    } catch {
      return value
    }
  }

  return value
}

function mapLikeToObject(value: unknown): Record<string, unknown> | undefined {
  const unwrapped = unwrapDataItem(value)
  if (unwrapped instanceof Map) return Object.fromEntries(unwrapped.entries())
  if (unwrapped && typeof unwrapped === 'object' && !Array.isArray(unwrapped)) {
    return unwrapped as Record<string, unknown>
  }

  return undefined
}

function toNameSpacesRecord(value: unknown): Record<string, Record<string, boolean>> {
  const unwrapped = unwrapDataItem(value)

  if (unwrapped instanceof Map) {
    return namespacesMapToRecord(unwrapped as Map<string, Map<string, boolean>>)
  }

  if (unwrapped && typeof unwrapped === 'object' && !Array.isArray(unwrapped)) {
    return Object.fromEntries(
      Object.entries(unwrapped as Record<string, unknown>).map(([namespace, elements]) => {
        if (elements instanceof Map) return [namespace, Object.fromEntries(elements.entries())]
        if (elements && typeof elements === 'object') return [namespace, elements as Record<string, boolean>]
        return [namespace, {}]
      })
    )
  }

  return {}
}

function toDeviceRequestInfo(value: unknown): MdocDeviceRequestInfo | undefined {
  const info = mapLikeToObject(value)
  if (!info) return undefined

  const useCasesValue = info.useCases
  if (!Array.isArray(useCasesValue)) return info as MdocDeviceRequestInfo

  const useCases = useCasesValue.map((useCaseValue) => {
    const useCase = mapLikeToObject(useCaseValue)
    return (useCase ?? (useCaseValue as Record<string, unknown>)) as MdocDeviceRequestUseCase
  })

  return { ...info, useCases } as MdocDeviceRequestInfo
}

export function parseDcApiDeviceRequest(deviceRequestBase64Url: string): MdocDcApiParsedDeviceRequest {
  const deviceRequestBytes = TypedArrayEncoder.fromBase64(deviceRequestBase64Url)
  const decoded = unwrapDataItem(cborDecode(deviceRequestBytes))

  if (!decoded || typeof decoded !== 'object') {
    throw new MdocError('Invalid DeviceRequest: expected CBOR map')
  }

  const version = getMapValue(decoded, 'version')
  if (typeof version !== 'string') {
    throw new MdocError('Invalid DeviceRequest: missing or invalid version')
  }

  const docRequestsValue = getMapValue(decoded, 'docRequests')
  if (!Array.isArray(docRequestsValue)) {
    throw new MdocError('Invalid DeviceRequest: missing docRequests array')
  }

  const documentRequests: MdocDcApiParsedDocumentRequest[] = docRequestsValue.map((docRequestValue, index) => {
    const itemsRequestValue = getMapValue(docRequestValue, 'itemsRequest')
    if (!itemsRequestValue) {
      throw new MdocError(`Invalid DeviceRequest: docRequests[${index}] missing itemsRequest`)
    }

    const itemsRequestData = unwrapDataItem(itemsRequestValue)
    const docType = getMapValue(itemsRequestData, 'docType')
    if (typeof docType !== 'string') {
      throw new MdocError(`Invalid DeviceRequest: docRequests[${index}] has invalid docType`)
    }

    const nameSpaces = toNameSpacesRecord(getMapValue(itemsRequestData, 'nameSpaces'))
    const readerAuth = getMapValue(docRequestValue, 'readerAuth') as ReaderAuth | undefined

    return readerAuth ? { docType, nameSpaces, readerAuth } : { docType, nameSpaces }
  })

  const deviceRequestInfo = toDeviceRequestInfo(getMapValue(decoded, 'deviceRequestInfo'))
  const readerAuthAll = getMapValue(decoded, 'readerAuthAll') as ReaderAuth[] | undefined

  return {
    version,
    documentRequests,
    deviceRequestInfo,
    readerAuthAll,
  }
}
