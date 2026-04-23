import { describe, expect, it } from 'vitest'
import { buildDisclosureFrameForPayload } from '../disclosureFrame'

describe('buildDisclosureFrameForPayload', () => {
  it('marks primitive values as true', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({ name: 'Alice', age: 30, active: true })

    expect(disclosureFrame).toEqual({
      name: true,
      age: true,
      active: true,
    })
  })

  it('recursively builds frame for non-empty nested objects', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({ address: { street: '123 Main St', city: 'Springfield' } })

    expect(disclosureFrame).toEqual({
      address: { street: true, city: true },
    })
  })

  it('marks empty objects as false', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({ meta: {} })

    expect(disclosureFrame).toEqual({ meta: false })
  })

  it('marks array of primitives as array of true', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({ tags: ['foo', 'bar', 42] })

    expect(disclosureFrame).toEqual({
      tags: [true, true, true],
    })
  })

  it('recursively builds frame for array of objects', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({ items: [{ name: 'Alice' }, { name: 'Bob' }] })

    expect(disclosureFrame).toEqual({
      items: [{ name: true }, { name: true }],
    })
  })

  it('handles mixed arrays of objects and primitives', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({ items: [{ name: 'Alice' }, 'raw', 42] })

    expect(disclosureFrame).toEqual({
      items: [{ name: true }, true, true],
    })
  })

  it('builds frame for a complex nested payload combining all branches', () => {
    const disclosureFrame = buildDisclosureFrameForPayload({
      sub: 'user-123',
      address: { street: '1 Main St', city: 'Springfield' },
      emptyMeta: {},
      tags: ['a', 'b'],
      credentials: [{ type: 'DriversLicense', number: 'DL-001' }, { type: 'Passport' }],
    })

    expect(disclosureFrame).toEqual({
      sub: true,
      address: { street: true, city: true },
      emptyMeta: false,
      tags: [true, true],
      credentials: [{ type: true, number: true }, { type: true }],
    })
  })
})
