import { getAgentOptions } from '../../../../tests'
import { Agent } from '../../../agent/Agent'
import { PublicJwk } from '../../kms'
import { X509Service } from '../../x509'
import { Mdoc } from '../Mdoc'
import { MdocRecord } from '../repository'

async function createMdocAndStore(agent: Agent) {
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
      },
    },
  })

  const record = MdocRecord.fromMdoc(mdoc)
  await agent.mdoc.store({ record })

  return { record }
}

describe('mdoc dcapi request resolution', () => {
  test('resolves matching credentials when all requested namespaces exist', async () => {
    const agent = new Agent(getAgentOptions('mdoc-dcapi-resolve-match', {}))
    await agent.initialize()

    try {
      const { record } = await createMdocAndStore(agent)

      const readerKey = await agent.kms.createKey({
        type: {
          kty: 'EC',
          crv: 'P-256',
        },
      })
      const readerPublicJwk = PublicJwk.fromPublicJwk(readerKey.publicJwk)

      const readerCertificate = await X509Service.createCertificate(agent.context, {
        issuer: 'C=US,CN=credo-reader',
        authorityKey: PublicJwk.fromPublicJwk(readerKey.publicJwk),
      })

      const dcApiRequest = await agent.mdoc.createDcApiRequest({
        documentRequests: [
          {
            docType: 'org.iso.18013.5.1.mDL',
            nameSpaces: {
              'org.iso.18013.5.1': {
                family_name: true,
                given_name: true,
              },
            },
            readerAuth: {
              readerKey: readerPublicJwk,
              x5chain: [readerCertificate.toString('pem')],
            },
          },
        ],
        nonce: new Uint8Array(16).fill(7),
        recipientPublicJwk: readerPublicJwk,
      })

      const resolution = await agent.mdoc.resolveDcApiRequest({
        deviceRequest: dcApiRequest.deviceRequest,
      })

      console.log('\n\n\n\n Resolution result: ', JSON.stringify(resolution, null, 2))
      expect(resolution.parsedRequest.documentRequests).toHaveLength(1)
      expect(resolution.matches).toHaveLength(1)
      expect(resolution.matches[0].matchingRecords.map((r) => r.id)).toContain(record.id)
    } finally {
      await agent.shutdown()
    }
  })

  test('can relax matching to docType only when requested namespaces are missing', async () => {
    const agent = new Agent(getAgentOptions('mdoc-dcapi-resolve-missing', {}))
    await agent.initialize()

    try {
      const { record } = await createMdocAndStore(agent)

      const readerKey = await agent.kms.createKey({
        type: {
          kty: 'EC',
          crv: 'P-256',
        },
      })
      const readerPublicJwk = PublicJwk.fromPublicJwk(readerKey.publicJwk)

      const dcApiRequest = await agent.mdoc.createDcApiRequest({
        documentRequests: [
          {
            docType: 'org.iso.18013.5.1.mDL',
            nameSpaces: {
              'org.iso.18013.5.1': {
                family_name: true,
                missing_element: true,
              },
            },
          },
        ],
        nonce: new Uint8Array(16).fill(9),
        recipientPublicJwk: readerPublicJwk,
      })

      const strictResolution = await agent.mdoc.resolveDcApiRequest({
        deviceRequest: dcApiRequest.deviceRequest,
      })
      expect(strictResolution.matches[0].matchingRecords).toHaveLength(0)

      const relaxedResolution = await agent.mdoc.resolveDcApiRequest({
        deviceRequest: dcApiRequest.deviceRequest,
        requireAllNamespaces: false,
      })
      expect(relaxedResolution.matches[0].matchingRecords.map((r) => r.id)).toContain(record.id)
    } finally {
      await agent.shutdown()
    }
  })
})
