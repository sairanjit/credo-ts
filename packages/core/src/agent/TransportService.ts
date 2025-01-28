import type { DidDocument } from '../modules/dids'
import type {
  TransportSession,
  TransportSessionRemovedEvent,
  TransportSessionRepository,
  TransportSessionSavedEvent,
} from '../transport'

import { DID_COMM_TRANSPORT_QUEUE, InjectionSymbols } from '../constants'
import { CredoError } from '../error'
import { inject, injectable } from '../plugins'
import { TransportEventTypes } from '../transport'

import { EventEmitter } from './EventEmitter'
import { AgentContext } from './context'

@injectable()
export class TransportService {
  private agentContext: AgentContext
  private eventEmitter: EventEmitter
  private transportSessionRepository: TransportSessionRepository

  public constructor(
    agentContext: AgentContext,
    eventEmitter: EventEmitter,
    @inject(InjectionSymbols.TransportSessionRepository) transportSessionRepository: TransportSessionRepository
  ) {
    this.agentContext = agentContext
    this.eventEmitter = eventEmitter
    this.transportSessionRepository = transportSessionRepository
  }

  public async saveSession(session: TransportSession) {
    if (session.connectionId) {
      const oldSessions = await this.getExistingSessionsForConnectionIdAndType(session.connectionId, session.type)

      for await (const oldSession of oldSessions) {
        if (oldSession && oldSession.id !== session.id) {
          await this.removeSession(oldSession)
        }
      }
    }
    await this.transportSessionRepository.addTransportSessionToSessionTable(session)

    this.eventEmitter.emit<TransportSessionSavedEvent>(this.agentContext, {
      type: TransportEventTypes.TransportSessionSaved,
      payload: {
        session,
      },
    })
  }

  public findSessionByConnectionId(connectionId: string) {
    return this.transportSessionRepository.findTransportSessionByConnectionId(connectionId)
  }

  public async setConnectionIdForSession(sessionId: string, connectionId: string) {
    const session = await this.findSessionById(sessionId)
    if (!session) {
      throw new CredoError(`Session not found with id ${sessionId}`)
    }
    session.connectionId = connectionId
    await this.saveSession(session)
  }

  public hasInboundEndpoint(didDocument: DidDocument): boolean {
    return Boolean(didDocument.didCommServices?.find((s) => s.serviceEndpoint !== DID_COMM_TRANSPORT_QUEUE))
  }

  public findSessionById(sessionId: string) {
    return this.transportSessionRepository.findTransportSessionById(sessionId)
  }

  public async removeSession(session: TransportSession) {
    await this.transportSessionRepository.removeTransportSessionById(session.id)
    this.eventEmitter.emit<TransportSessionRemovedEvent>(this.agentContext, {
      type: TransportEventTypes.TransportSessionRemoved,
      payload: {
        session,
      },
    })
  }

  private async getExistingSessionsForConnectionIdAndType(connectionId: string, type: string) {
    return await this.transportSessionRepository.findExistingSessionsForConnectionIdAndType(connectionId, type)
  }
}
