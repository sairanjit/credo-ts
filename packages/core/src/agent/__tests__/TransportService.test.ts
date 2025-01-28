import { Subject } from 'rxjs'

import { agentDependencies, getAgentContext, getMockConnection } from '../../../tests/helpers'
import { DidExchangeRole } from '../../modules/connections'
import { EventEmitter } from '../EventEmitter'
import { TransportService } from '../TransportService'

import { DummyTransportSession } from './stubs'

import { InMemoryTransportSessionRepository } from '@credo-ts/core'

describe('TransportService', () => {
  describe('removeSession', () => {
    let transportService: TransportService

    beforeEach(() => {
      transportService = new TransportService(
        getAgentContext(),
        new EventEmitter(agentDependencies, new Subject()),
        new InMemoryTransportSessionRepository()
      )
    })

    test(`remove session saved for a given connection`, async () => {
      const connection = getMockConnection({ id: 'test-123', role: DidExchangeRole.Responder })
      const session = new DummyTransportSession('dummy-session-123')
      session.connectionId = connection.id

      await transportService.saveSession(session)
      expect(transportService.findSessionByConnectionId(connection.id)).toEqual(session)

      await transportService.removeSession(session)
      expect(transportService.findSessionByConnectionId(connection.id)).toEqual(undefined)
    })
  })
})
