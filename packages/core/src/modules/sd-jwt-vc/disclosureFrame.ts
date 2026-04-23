import { isObject } from 'class-validator'
import type { JsonObject } from '../../types'

type DisclosureFrame = {
  [key: string]: boolean | DisclosureFrame
}

export function buildDisclosureFrameForPayload(input: JsonObject): DisclosureFrame {
  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => {
      if (Array.isArray(value)) {
        return [key, value.map((item) => {
          if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
            return buildDisclosureFrameForPayload(item);
          }
          return true;
        })];
      }
      if (isObject(value)) {
        if (Object.keys(value).length === 0) return [key, false];
        return [key, buildDisclosureFrameForPayload(value)]
      }
      return [key, true]
    })
  )
}
