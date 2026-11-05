import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { networkInterfaces } from "node:os";
import { dirname } from "node:path";
import type { HostKeyHandover } from "@openbot/contracts/host-key-handover";
import type { AvatarColor, CentralAuthUser } from "@openbot/contracts/ipc";
import { isAvatarColor } from "@openbot/contracts/ipc";
import { isMobileConnectHostBinding, type MobileConnectHostBinding } from "@openbot/contracts/mobile-connect";
import { isBoolean, isDynamicRecord, isNumber, isString } from "@openbot/contracts/runtime-values";
import {
  SIGNAL_PROTOCOL_VERSION,
  type SignalClientMessage,
  type SignalServerMessage,
} from "@openbot/contracts/signal-protocol/messages";
import {
  REMOTE_TICKET_AUDIENCE,
  REMOTE_TICKET_PROTOCOL_VERSION,
  type RemoteMemberRole,
  type RemoteRole,
} from "@openbot/contracts/signal-protocol/ticket";
import { createOpenBotLogger, toLogValue } from "@openbot/logging";
import { exportJWK, generateKeyPair, importJWK, type JWK, jwtVerify, SignJWT } from "jose";
import { type RawData, WebSocket, WebSocketServer } from "ws";

const logger = createOpenBotLogger("embedded-local-cloud");

const DEFAULT_LOCAL_CLOUD_PORT = 3100;
const TICKET_TTL_SECONDS = 5 * 60;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const MOBILE_TICKET_TTL_MS = 5 * 60 * 1_000;

interface StoredUser {
  id: string;
  email: string;
  name: string | null;
  avatarMimeType: string | null;
  avatarBase64: string | null;
  avatarVersion: number;
  analyticsEnabled: boolean | null;
  chatColor: AvatarColor | null;
}

interface StoredAccountSession {
  sessionId: string;
  token: string;
  userId: string;
  kind: "desktop" | "mobile";
  deviceId: string | null;
  name: string;
  platform: "ios" | "android" | "unknown";
  via: "code" | "link";
  host: MobileConnectHostBinding | null;
  connectedAt: number;
  lastActiveAt: number;
}

interface StoredRemoteHost {
  hostId: string;
  name: string;
  ownerUserId: string;
  ownerMembershipId: string;
  authEpoch: number;
  machineToken: string;
  devicePublicKey: string | null;
  logoKey: string | null;
  logoMimeType: string | null;
  logoBase64: string | null;
  keyHandovers: HostKeyHandover[];
}

interface StoredRemoteMembership {
  membershipId: string;
  hostId: string;
  userId: string;
  role: RemoteMemberRole;
  status: "active" | "revoked";
  createdAt: number;
}

interface StoredRemoteInvite {
  inviteId: string;
  token: string;
  hostId: string;
  email: string | null;
  role: "admin" | "member";
  expiresAt: number;
  usedAt: number | null;
  revokedAt: number | null;
  permanent: boolean;
  useCount: number;
}

interface StoredMobileConnectLink {
  userId: string;
  host: MobileConnectHostBinding;
  token: string;
  createdAt: number;
}

interface PersistedLocalCloudState {
  version: 1;
  keyId: string;
  publicJwk: JWK;
  privateJwk: JWK;
  users: StoredUser[];
  sessions: StoredAccountSession[];
  hosts: StoredRemoteHost[];
  memberships: StoredRemoteMembership[];
  invites: StoredRemoteInvite[];
  mobileLinks: StoredMobileConnectLink[];
}

interface EphemeralEmailChallenge {
  challengeId: string;
  email: string;
  code: string;
  expiresAt: number;
  resendAt: number;
}

interface EphemeralMobileTicket {
  ticket: string;
  userId: string;
  host: MobileConnectHostBinding;
  expiresAt: number;
}

interface ActiveRemoteSession {
  sessionId: string;
  hostId: string;
  userId: string;
  membershipId: string;
  role: RemoteMemberRole;
  authEpoch: number;
  expiresAt: number;
}

interface VerifiedSignalToken {
  kind: "ticket" | "resume";
  peer: "host" | "client" | "ingress";
  sessionId: string;
  hostId: string;
  userId: string;
  membershipId: string;
  role: RemoteRole;
  authEpoch: number;
  sessionExpiresAt: number;
}

interface SignalClientEntry {
  connectionId: string;
  sessionId: string;
  userId: string;
  membershipId: string;
  role: RemoteMemberRole;
  sessionExpiresAt: number;
  socket: WebSocket;
}

interface SignalRoom {
  hostSocket: WebSocket | null;
  ingressSocket: WebSocket | null;
  clientsBySession: Map<string, SignalClientEntry>;
  clientsByConnection: Map<string, SignalClientEntry>;
  waitingClientsBySession: Map<string, SignalClientEntry>;
}

export interface EmbeddedLocalCloud {
  readonly port: number;
  readonly localApiUrl: string;
  resolveMobileConnectApiUrl(): string;
  close(): Promise<void>;
}

function isTailscaleIpv4(ip: string): boolean {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first = -1, second = -1] = parts;
  return first === 100 && second >= 64 && second <= 127;
}

function isPrivateLanIpv4(ip: string): boolean {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first = -1, second = -1] = parts;
  return first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
}

/**
 * Picks the most reachable IPv4 address of this Mac for Mobile Connect QR pairing:
 * 1. Explicit `OPENBOT_LOCAL_HOST` override if set,
 * 2. Tailscale IPv4 (`100.64.0.0/10`) so pairing works both on home Wi-Fi and over 4G/5G,
 * 3. Private LAN IPv4 (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`),
 * 4. Loopback `127.0.0.1` fallback.
 */
export function resolveReachableLocalHost(env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env.OPENBOT_LOCAL_HOST?.trim();
  if (explicit) return explicit;
  const interfaces = networkInterfaces();
  const tailscaleCandidates: string[] = [];
  const lanCandidates: string[] = [];
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      const family = typeof entry.family === "number" ? (entry.family === 4 ? "IPv4" : "IPv6") : entry.family;
      if (family !== "IPv4" || entry.internal) continue;
      if (isTailscaleIpv4(entry.address)) {
        tailscaleCandidates.push(entry.address);
      } else if (isPrivateLanIpv4(entry.address)) {
        lanCandidates.push(entry.address);
      }
    }
  }
  return tailscaleCandidates[0] ?? lanCandidates[0] ?? "127.0.0.1";
}

export async function startEmbeddedLocalCloud(options: {
  storagePath: string;
  preferredPort?: number;
  env?: NodeJS.ProcessEnv;
}): Promise<EmbeddedLocalCloud> {
  const env = options.env ?? process.env;
  const preferredPort =
    options.preferredPort ?? (Number(env.OPENBOT_LOCAL_CLOUD_PORT ?? DEFAULT_LOCAL_CLOUD_PORT) || DEFAULT_LOCAL_CLOUD_PORT);

  const loaded = await loadOrCreatePersistedState(options.storagePath);
  const { state, privateKey, publicKey } = loaded;

  let saveChain = Promise.resolve();
  const persistState = (): Promise<void> => {
    const snapshot = JSON.stringify(state, null, 2);
    saveChain = saveChain
      .then(async () => {
        const tempPath = `${options.storagePath}.${randomUUID()}.tmp`;
        await mkdir(dirname(options.storagePath), { recursive: true });
        await writeFile(tempPath, snapshot, { mode: 0o600 });
        await rename(tempPath, options.storagePath);
      })
      .catch((error) => {
        logger.warn("Failed to persist embedded local cloud state.", toLogValue(error));
      });
    return saveChain;
  };

  const emailChallenges = new Map<string, EphemeralEmailChallenge>();
  const mobileTickets = new Map<string, EphemeralMobileTicket>();
  const remoteSessions = new Map<string, ActiveRemoteSession>();
  const rooms = new Map<string, SignalRoom>();
  const userSockets = new Map<string, Set<WebSocket>>();

  const trackUserSocket = (userId: string, socket: WebSocket) => {
    let set = userSockets.get(userId);
    if (!set) {
      set = new Set();
      userSockets.set(userId, set);
    }
    set.add(socket);
    socket.once("close", () => {
      set?.delete(socket);
      if (set?.size === 0) userSockets.delete(userId);
    });
  };

  const broadcastToUser = (userId: string, message: SignalServerMessage) => {
    const payload = JSON.stringify(message);
    for (const socket of userSockets.get(userId) ?? []) {
      if (socket.readyState === WebSocket.OPEN) socket.send(payload);
    }
  };

  const getRoom = (hostId: string): SignalRoom => {
    const key = hostId.toLowerCase();
    let room = rooms.get(key);
    if (!room) {
      room = {
        hostSocket: null,
        ingressSocket: null,
        clientsBySession: new Map(),
        clientsByConnection: new Map(),
        waitingClientsBySession: new Map(),
      };
      rooms.set(key, room);
    }
    return room;
  };

  const formatUser = (user: StoredUser): CentralAuthUser => ({
    id: user.id,
    email: user.email,
    name: user.name,
    avatarUrl: user.avatarBase64 ? `/v1/avatars/${encodeURIComponent(user.id)}?v=${user.avatarVersion}` : null,
    analyticsEnabled: false,
    ...(user.chatColor !== null ? { chatColor: user.chatColor } : {}),
  });

  const findOrCreateUserByEmail = (rawEmail: string): StoredUser => {
    const email = rawEmail.trim().toLowerCase();
    let user = state.users.find((entry) => entry.email.toLowerCase() === email);
    if (!user) {
      const localPart = email.split("@")[0] || "Owner";
      const defaultName = localPart
        .replace(/[._-]+/gu, " ")
        .replace(/\b\w/gu, (char) => char.toUpperCase())
        .slice(0, 60);
      user = {
        id: randomUUID(),
        email,
        name: defaultName || "Owner",
        avatarMimeType: null,
        avatarBase64: null,
        avatarVersion: 0,
        analyticsEnabled: false,
        chatColor: null,
      };
      state.users.push(user);
    }
    return user;
  };

  const readSessionFromRequest = (req: IncomingMessage): { session: StoredAccountSession; user: StoredUser } | null => {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return null;
    const token = header.slice("Bearer ".length).trim();
    if (!token) return null;
    const session = state.sessions.find((entry) => entry.token === token);
    if (!session) return null;
    const user = state.users.find((entry) => entry.id === session.userId);
    if (!user) return null;
    session.lastActiveAt = Date.now();
    return { session, user };
  };

  const signSignalJwt = async (claims: {
    kind: "ticket" | "resume";
    peer: "host" | "client" | "ingress";
    sessionId: string;
    hostId: string;
    userId: string;
    membershipId: string;
    role: RemoteRole;
    authEpoch: number;
    sessionExpiresAt: number;
    clientPublicKey?: string;
    ttlSeconds?: number;
  }): Promise<{ token: string; expiresAt: number }> => {
    const nowSeconds = Math.floor(Date.now() / 1_000);
    const expSeconds = Math.min(claims.sessionExpiresAt, nowSeconds + (claims.ttlSeconds ?? TICKET_TTL_SECONDS));
    const token = await new SignJWT({
      kind: claims.kind,
      peer: claims.peer,
      sessionId: claims.sessionId,
      hostId: claims.hostId,
      userId: claims.userId,
      membershipId: claims.membershipId,
      role: claims.role,
      authEpoch: claims.authEpoch,
      protocolMinimum: REMOTE_TICKET_PROTOCOL_VERSION,
      protocolMaximum: REMOTE_TICKET_PROTOCOL_VERSION,
      sessionExpiresAt: claims.sessionExpiresAt,
      ...(claims.clientPublicKey ? { clientPublicKey: claims.clientPublicKey } : {}),
    })
      .setProtectedHeader({ alg: "ES256", kid: state.keyId, typ: "JWT" })
      .setAudience(claims.kind === "resume" ? "openbot-signal-resume" : REMOTE_TICKET_AUDIENCE)
      .setJti(randomUUID())
      .setIssuedAt(nowSeconds)
      .setExpirationTime(expSeconds)
      .sign(privateKey);
    return { token, expiresAt: expSeconds * 1_000 };
  };

  const verifySignalJwt = async (token: string): Promise<VerifiedSignalToken | null> => {
    try {
      const { payload } = await jwtVerify(token, publicKey, {
        algorithms: ["ES256"],
        audience: [REMOTE_TICKET_AUDIENCE, "openbot-signal-resume"],
      });
      if (
        (payload.peer !== "host" && payload.peer !== "client" && payload.peer !== "ingress") ||
        !isString(payload.sessionId) ||
        !isString(payload.hostId) ||
        !isString(payload.userId) ||
        !isString(payload.membershipId) ||
        (payload.role !== "host" &&
          payload.role !== "owner" &&
          payload.role !== "admin" &&
          payload.role !== "member") ||
        !isNumber(payload.authEpoch) ||
        !isNumber(payload.sessionExpiresAt)
      ) {
        return null;
      }
      return {
        kind: payload.kind === "resume" ? "resume" : "ticket",
        peer: payload.peer,
        sessionId: payload.sessionId,
        hostId: payload.hostId,
        userId: payload.userId,
        membershipId: payload.membershipId,
        role: payload.role,
        authEpoch: payload.authEpoch,
        sessionExpiresAt: payload.sessionExpiresAt,
      };
    } catch {
      return null;
    }
  };

  let boundPort = preferredPort;

  const signalUrlForRequest = (req: IncomingMessage): string => {
    const hostHeader = req.headers.host?.trim();
    if (hostHeader) return `ws://${hostHeader}/v1/signal`;
    return `ws://${resolveReachableLocalHost(env)}:${boundPort}/v1/signal`;
  };

  const server = createServer((req, res) => {
    void handleHttpRequest(req, res).catch((error) => {
      logger.warn("Unhandled error in embedded local cloud HTTP handler.", toLogValue(error));
      if (!res.headersSent) {
        sendJson(res, 500, { error: { code: "internal_error", message: "Internal local cloud error." } });
      }
    });
  });

  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
    if (url.pathname !== "/v1/signal") {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      handleSignalSocket(ws);
    });
  });

  const sendSignalFrame = (socket: WebSocket, frame: SignalServerMessage) => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(frame));
    }
  };

  const handleSignalSocket = (socket: WebSocket) => {
    let authenticated: {
      peer: "host" | "client" | "ingress";
      hostId: string;
      sessionId: string;
      userId: string;
      membershipId: string;
      role: RemoteRole;
      authEpoch: number;
      sessionExpiresAt: number;
      connectionId: string | null;
    } | null = null;

    socket.on("message", (raw: RawData) => {
      void (async () => {
        let parsed: SignalClientMessage;
        try {
          parsed = JSON.parse(raw.toString()) as SignalClientMessage;
        } catch {
          sendSignalFrame(socket, {
            type: "error",
            version: SIGNAL_PROTOCOL_VERSION,
            code: "invalid_message",
            message: "Invalid Signal JSON frame.",
          });
          socket.close(1008, "Invalid message");
          return;
        }

        if (!authenticated) {
          if (parsed.type !== "hello") {
            sendSignalFrame(socket, {
              type: "error",
              version: SIGNAL_PROTOCOL_VERSION,
              code: "protocol_error",
              message: "Expected hello frame first.",
            });
            socket.close(1008, "Expected hello");
            return;
          }
          const verified = await verifySignalJwt(parsed.token);
          if (!verified) {
            sendSignalFrame(socket, {
              type: "error",
              version: SIGNAL_PROTOCOL_VERSION,
              code: "authentication_required",
              message: "Ticket invalid or expired.",
            });
            socket.close(1008, "Authentication required");
            return;
          }
          const host = state.hosts.find((entry) => entry.hostId.toLowerCase() === verified.hostId.toLowerCase());
          if (!host || host.authEpoch !== verified.authEpoch) {
            sendSignalFrame(socket, {
              type: "error",
              version: SIGNAL_PROTOCOL_VERSION,
              code: "session_revoked",
              message: "Host session was revoked.",
            });
            socket.close(4000, "Session revoked");
            return;
          }

          const resume = await signSignalJwt({
            kind: "resume",
            peer: parsed.peer,
            sessionId: verified.sessionId,
            hostId: host.hostId,
            userId: verified.userId,
            membershipId: verified.membershipId,
            role: verified.role,
            authEpoch: host.authEpoch,
            sessionExpiresAt: verified.sessionExpiresAt,
            ttlSeconds: 24 * 60 * 60,
          });

          const room = getRoom(host.hostId);
          trackUserSocket(verified.userId, socket);

          if (parsed.peer === "ingress") {
            if (room.ingressSocket && room.ingressSocket !== socket) {
              room.ingressSocket.close(1000, "Replaced by new ingress socket");
            }
            room.ingressSocket = socket;
            authenticated = {
              peer: "ingress",
              hostId: host.hostId,
              sessionId: verified.sessionId,
              userId: verified.userId,
              membershipId: verified.membershipId,
              role: verified.role,
              authEpoch: host.authEpoch,
              sessionExpiresAt: verified.sessionExpiresAt,
              connectionId: null,
            };
            sendSignalFrame(socket, {
              type: "ready",
              version: SIGNAL_PROTOCOL_VERSION,
              connectionId: null,
              resumeToken: resume.token,
              iceServers: [],
              capabilities: ["telegram", "ingress-queue"],
            });
            if (parsed.webhookRoute) {
              sendSignalFrame(socket, { type: "webhook-ready", version: SIGNAL_PROTOCOL_VERSION });
            }
            if (parsed.githubRoute) {
              sendSignalFrame(socket, { type: "github-ready", version: SIGNAL_PROTOCOL_VERSION });
            }
            return;
          }

          if (parsed.peer === "host") {
            if (room.hostSocket && room.hostSocket !== socket) {
              room.hostSocket.close(1000, "Replaced by new host socket");
            }
            room.hostSocket = socket;
            authenticated = {
              peer: "host",
              hostId: host.hostId,
              sessionId: verified.sessionId,
              userId: verified.userId,
              membershipId: verified.membershipId,
              role: verified.role,
              authEpoch: host.authEpoch,
              sessionExpiresAt: verified.sessionExpiresAt,
              connectionId: null,
            };
            sendSignalFrame(socket, {
              type: "ready",
              version: SIGNAL_PROTOCOL_VERSION,
              connectionId: null,
              resumeToken: resume.token,
              iceServers: [],
            });

            // Attach any waiting client sockets now that the host is online.
            for (const [waitingSessionId, waitingEntry] of [...room.waitingClientsBySession.entries()]) {
              room.waitingClientsBySession.delete(waitingSessionId);
              if (waitingEntry.socket.readyState !== WebSocket.OPEN) continue;
              const existing = room.clientsBySession.get(waitingSessionId);
              const resumed = Boolean(existing);
              if (existing) room.clientsByConnection.delete(existing.connectionId);
              room.clientsBySession.set(waitingSessionId, waitingEntry);
              room.clientsByConnection.set(waitingEntry.connectionId, waitingEntry);
              const clientResume = await signSignalJwt({
                kind: "resume",
                peer: "client",
                sessionId: waitingEntry.sessionId,
                hostId: host.hostId,
                userId: waitingEntry.userId,
                membershipId: waitingEntry.membershipId,
                role: waitingEntry.role,
                authEpoch: host.authEpoch,
                sessionExpiresAt: waitingEntry.sessionExpiresAt,
                ttlSeconds: 24 * 60 * 60,
              });
              sendSignalFrame(waitingEntry.socket, {
                type: "ready",
                version: SIGNAL_PROTOCOL_VERSION,
                connectionId: waitingEntry.connectionId,
                resumeToken: clientResume.token,
                iceServers: [],
              });
              sendSignalFrame(socket, {
                type: "peer-ready",
                version: SIGNAL_PROTOCOL_VERSION,
                connectionId: waitingEntry.connectionId,
                sessionId: waitingEntry.sessionId,
                userId: waitingEntry.userId,
                membershipId: waitingEntry.membershipId,
                role: waitingEntry.role,
                sessionExpiresAt: waitingEntry.sessionExpiresAt,
                resumed,
              });
            }
            return;
          }

          // Client peer
          const clientRole: RemoteMemberRole =
            verified.role === "owner" || verified.role === "admin" || verified.role === "member"
              ? verified.role
              : "owner";
          const connectionId = randomUUID();
          const clientEntry: SignalClientEntry = {
            connectionId,
            sessionId: verified.sessionId,
            userId: verified.userId,
            membershipId: verified.membershipId,
            role: clientRole,
            sessionExpiresAt: verified.sessionExpiresAt,
            socket,
          };
          authenticated = {
            peer: "client",
            hostId: host.hostId,
            sessionId: verified.sessionId,
            userId: verified.userId,
            membershipId: verified.membershipId,
            role: clientRole,
            authEpoch: host.authEpoch,
            sessionExpiresAt: verified.sessionExpiresAt,
            connectionId,
          };

          if (!room.hostSocket || room.hostSocket.readyState !== WebSocket.OPEN) {
            if (parsed.waitForHost) {
              room.waitingClientsBySession.set(verified.sessionId, clientEntry);
              sendSignalFrame(socket, {
                type: "host-waiting",
                version: SIGNAL_PROTOCOL_VERSION,
                resumeToken: resume.token,
              });
              return;
            }
            sendSignalFrame(socket, {
              type: "error",
              version: SIGNAL_PROTOCOL_VERSION,
              code: "host_unavailable",
              message: "Host is offline.",
            });
            socket.close(1008, "Host unavailable");
            return;
          }

          const previous = room.clientsBySession.get(verified.sessionId);
          const resumed = verified.kind === "resume" && Boolean(previous);
          if (previous) {
            room.clientsByConnection.delete(previous.connectionId);
            if (previous.socket !== socket && previous.socket.readyState === WebSocket.OPEN) {
              previous.socket.close(1000, "Replaced by new client socket");
            }
          }
          room.clientsBySession.set(verified.sessionId, clientEntry);
          room.clientsByConnection.set(connectionId, clientEntry);

          sendSignalFrame(socket, {
            type: "ready",
            version: SIGNAL_PROTOCOL_VERSION,
            connectionId,
            resumeToken: resume.token,
            iceServers: [],
          });
          sendSignalFrame(room.hostSocket, {
            type: "peer-ready",
            version: SIGNAL_PROTOCOL_VERSION,
            connectionId,
            sessionId: verified.sessionId,
            userId: verified.userId,
            membershipId: verified.membershipId,
            role: clientRole,
            sessionExpiresAt: verified.sessionExpiresAt,
            resumed,
          });
          return;
        }

        const room = getRoom(authenticated.hostId);

        if (parsed.type === "turn-refresh") {
          const resume = await signSignalJwt({
            kind: "resume",
            peer: authenticated.peer,
            sessionId: authenticated.sessionId,
            hostId: authenticated.hostId,
            userId: authenticated.userId,
            membershipId: authenticated.membershipId,
            role: authenticated.role,
            authEpoch: authenticated.authEpoch,
            sessionExpiresAt: authenticated.sessionExpiresAt,
            ttlSeconds: 24 * 60 * 60,
          });
          sendSignalFrame(socket, {
            type: "ready",
            version: SIGNAL_PROTOCOL_VERSION,
            connectionId: null,
            resumeToken: resume.token,
            iceServers: [],
          });
          return;
        }

        if (
          parsed.type === "offer" ||
          parsed.type === "answer" ||
          parsed.type === "ice-candidate" ||
          parsed.type === "ice-restart" ||
          parsed.type === "disconnect"
        ) {
          if (authenticated.peer === "host") {
            const target = room.clientsByConnection.get(parsed.connectionId);
            if (target && target.socket.readyState === WebSocket.OPEN) {
              sendSignalFrame(target.socket, parsed);
            }
            if (parsed.type === "disconnect" && target) {
              room.clientsByConnection.delete(parsed.connectionId);
              if (room.clientsBySession.get(target.sessionId) === target) {
                room.clientsBySession.delete(target.sessionId);
              }
            }
          } else if (authenticated.peer === "client") {
            if (room.hostSocket && room.hostSocket.readyState === WebSocket.OPEN) {
              sendSignalFrame(room.hostSocket, {
                ...parsed,
                connectionId: authenticated.connectionId ?? parsed.connectionId,
              });
            }
          }
        }
      })().catch((error) => {
        logger.warn("Error in embedded Signal WebSocket handler.", toLogValue(error));
      });
    });

    socket.on("close", () => {
      if (!authenticated) return;
      const room = getRoom(authenticated.hostId);
      if (authenticated.peer === "host" && room.hostSocket === socket) {
        room.hostSocket = null;
      } else if (authenticated.peer === "ingress" && room.ingressSocket === socket) {
        room.ingressSocket = null;
      } else if (authenticated.peer === "client") {
        const waiting = room.waitingClientsBySession.get(authenticated.sessionId);
        if (waiting?.socket === socket) {
          room.waitingClientsBySession.delete(authenticated.sessionId);
        }
        if (authenticated.connectionId) {
          const active = room.clientsByConnection.get(authenticated.connectionId);
          if (active?.socket === socket) {
            room.clientsByConnection.delete(authenticated.connectionId);
            if (room.clientsBySession.get(authenticated.sessionId) === active) {
              room.clientsBySession.delete(authenticated.sessionId);
            }
          }
        }
      }
    });
  };

  const handleHttpRequest = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? `127.0.0.1:${boundPort}`}`);
    const pathname = url.pathname;

    // 1. Health & JWKS
    if (method === "GET" && pathname === "/health/live") {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (method === "GET" && pathname === "/.well-known/jwks.json") {
      sendJson(res, 200, { keys: [state.publicJwk] });
      return;
    }

    // 2. Email sign-in (Desktop & Mobile) - auto-provides developmentCode: "111111"
    if (method === "POST" && pathname === "/v1/auth/email/start") {
      const body = await readJsonBody(req);
      const email = isDynamicRecord(body) && isString(body.email) ? body.email.trim().toLowerCase() : "";
      if (!email || !email.includes("@")) {
        sendError(res, 400, "invalid_email", "Invalid email address.");
        return;
      }
      const now = Date.now();
      const challenge: EphemeralEmailChallenge = {
        challengeId: randomUUID(),
        email,
        code: "111111",
        expiresAt: now + 10 * 60 * 1_000,
        resendAt: now + 5_000,
      };
      emailChallenges.set(challenge.challengeId, challenge);
      sendJson(res, 200, {
        challengeId: challenge.challengeId,
        expiresAt: challenge.expiresAt,
        resendAt: challenge.resendAt,
        developmentCode: challenge.code,
      });
      return;
    }

    if (method === "POST" && (pathname === "/v1/auth/email/verify" || pathname === "/v1/mobile-auth/email/verify")) {
      const body = await readJsonBody(req);
      const challengeId = isDynamicRecord(body) && isString(body.challengeId) ? body.challengeId : "";
      const challenge = emailChallenges.get(challengeId);
      const email = challenge?.email ?? "owner@openbot.local";
      emailChallenges.delete(challengeId);

      const user = findOrCreateUserByEmail(email);
      const isMobile = pathname === "/v1/mobile-auth/email/verify";
      const now = Date.now();
      const session: StoredAccountSession = {
        sessionId: randomUUID(),
        token: randomBytes(32).toString("base64url"),
        userId: user.id,
        kind: isMobile ? "mobile" : "desktop",
        deviceId: isDynamicRecord(body) && isString(body.deviceId) ? body.deviceId : null,
        name: isDynamicRecord(body) && isString(body.deviceName) ? body.deviceName : isMobile ? "iPhone" : "Mac",
        platform:
          isDynamicRecord(body) && (body.platform === "ios" || body.platform === "android") ? body.platform : "unknown",
        via: "code",
        host: null,
        connectedAt: now,
        lastActiveAt: now,
      };
      state.sessions.push(session);
      await persistState();
      sendJson(res, 200, {
        sessionToken: session.token,
        user: formatUser(user),
      });
      return;
    }

    if (method === "POST" && pathname === "/v1/auth/logout") {
      const auth = readSessionFromRequest(req);
      if (auth) {
        state.sessions = state.sessions.filter((entry) => entry.sessionId !== auth.session.sessionId);
        await persistState();
      }
      sendEmpty(res, 204);
      return;
    }

    // 3. Avatar download
    const avatarMatch = /^\/v1\/avatars\/([^/]+)$/u.exec(pathname);
    if (method === "GET" && avatarMatch) {
      const userId = decodeURIComponent(avatarMatch[1] ?? "");
      const user = state.users.find((entry) => entry.id === userId);
      if (!user?.avatarBase64 || !user.avatarMimeType) {
        sendError(res, 404, "not_found", "Avatar not found.");
        return;
      }
      const bytes = Buffer.from(user.avatarBase64, "base64");
      res.writeHead(200, {
        "Content-Type": user.avatarMimeType,
        "Content-Length": String(bytes.byteLength),
      });
      res.end(bytes);
      return;
    }

    // 4. Mobile Connect redeem (unauthenticated POST with one-time ticket or persistent link)
    if (method === "POST" && pathname === "/v1/mobile-auth/redeem") {
      const body = await readJsonBody(req);
      const ticket = isDynamicRecord(body) && isString(body.ticket) ? body.ticket.trim() : "";
      if (!ticket) {
        sendError(res, 400, "invalid_ticket", "Missing Mobile Connect ticket.");
        return;
      }
      const now = Date.now();
      let matchedUser: StoredUser | undefined;
      let matchedHost: MobileConnectHostBinding | undefined;
      let via: "code" | "link" = "code";

      const oneTime = mobileTickets.get(ticket);
      if (oneTime && oneTime.expiresAt > now) {
        mobileTickets.delete(ticket);
        matchedUser = state.users.find((entry) => entry.id === oneTime.userId);
        matchedHost = oneTime.host;
        via = "code";
      } else {
        const link = state.mobileLinks.find((entry) => entry.token === ticket);
        if (link) {
          matchedUser = state.users.find((entry) => entry.id === link.userId);
          matchedHost = link.host;
          via = "link";
        }
      }

      if (!matchedUser || !matchedHost) {
        sendError(res, 401, "invalid_ticket", "Mobile Connect code expired or invalid.");
        return;
      }

      const deviceId = isDynamicRecord(body) && isString(body.deviceId) ? body.deviceId : null;
      const deviceName = isDynamicRecord(body) && isString(body.deviceName) ? body.deviceName : "iPhone";
      const platform =
        isDynamicRecord(body) && (body.platform === "ios" || body.platform === "android") ? body.platform : "ios";

      if (deviceId) {
        state.sessions = state.sessions.filter(
          (entry) => !(entry.kind === "mobile" && entry.userId === matchedUser.id && entry.deviceId === deviceId),
        );
      }

      const session: StoredAccountSession = {
        sessionId: randomUUID(),
        token: randomBytes(32).toString("base64url"),
        userId: matchedUser.id,
        kind: "mobile",
        deviceId,
        name: deviceName,
        platform,
        via,
        host: matchedHost,
        connectedAt: now,
        lastActiveAt: now,
      };
      state.sessions.push(session);
      await persistState();

      sendJson(res, 200, {
        sessionToken: session.token,
        user: formatUser(matchedUser),
        host: matchedHost,
      });
      return;
    }

    // 5. Host machine-token routes (/v2/remote/hosts/:hostId/ticket, webhook-route, etc.)
    const hostActionMatch = /^\/v2\/remote\/hosts\/([^/]+)\/([a-z-]+)$/u.exec(pathname);
    if (hostActionMatch && method !== "GET") {
      const hostId = decodeURIComponent(hostActionMatch[1] ?? "");
      const action = hostActionMatch[2] ?? "";
      const host = state.hosts.find((entry) => entry.hostId.toLowerCase() === hostId.toLowerCase());

      if (action === "ticket" && method === "POST") {
        const body = await readJsonBody(req);
        const machineToken = isDynamicRecord(body) && isString(body.machineToken) ? body.machineToken : "";
        if (!host || host.machineToken !== machineToken) {
          sendError(res, 401, "unauthorized", "Invalid host credential.");
          return;
        }
        const sessionExpiresAt = Math.floor((Date.now() + SESSION_TTL_MS) / 1_000);
        const signed = await signSignalJwt({
          kind: "ticket",
          peer: "host",
          sessionId: randomUUID(),
          hostId: host.hostId,
          userId: host.ownerUserId,
          membershipId: host.ownerMembershipId,
          role: "host",
          authEpoch: host.authEpoch,
          sessionExpiresAt,
        });
        sendJson(res, 200, {
          ticket: signed.token,
          expiresAt: signed.expiresAt,
          signalUrl: signalUrlForRequest(req),
        });
        return;
      }

      if (action === "key-handover" && method === "POST") {
        const body = await readJsonBody(req);
        const machineToken = isDynamicRecord(body) && isString(body.machineToken) ? body.machineToken : "";
        if (!host || host.machineToken !== machineToken) {
          sendError(res, 401, "unauthorized", "Invalid host credential.");
          return;
        }
        if (isDynamicRecord(body) && isDynamicRecord(body.handover) && isString(body.handover.newPublicKey)) {
          host.devicePublicKey = body.handover.newPublicKey;
          host.keyHandovers.push(body.handover as unknown as HostKeyHandover);
          await persistState();
        }
        sendEmpty(res, 204);
        return;
      }

      if (
        (action === "webhook-route" ||
          action === "slack-route" ||
          action === "discord-route" ||
          action === "telegram-route") &&
        method === "POST"
      ) {
        sendJson(res, 200, { ticket: randomBytes(24).toString("base64url") });
        return;
      }

      if (action === "github-route" && method === "POST") {
        sendJson(res, 200, { ticket: randomBytes(24).toString("base64url"), repositories: [] });
        return;
      }

      if (action === "webhook-routes" && method === "POST") {
        const body = await readJsonBody(req);
        const routeId = isDynamicRecord(body) && isString(body.routeId) ? body.routeId : randomUUID();
        sendJson(res, 200, { routeId });
        return;
      }

      if (action === "webhook-routes" && method === "DELETE") {
        sendEmpty(res, 204);
        return;
      }

      if (
        (action === "live-activity" ||
          action === "notification" ||
          action === "android-notification" ||
          action === "slack-disconnect" ||
          action === "discord-disconnect" ||
          action === "telegram-disconnect") &&
        method === "POST"
      ) {
        sendEmpty(res, 204);
        return;
      }

      if (action === "telegram-link" && method === "POST") {
        sendError(res, 503, "telegram_not_configured", "Telegram relay is not configured on local cloud.");
        return;
      }
    }

    // 6. Invite preview (unauthenticated)
    if (method === "POST" && pathname === "/v2/remote/invites/preview") {
      const body = await readJsonBody(req);
      const token = isDynamicRecord(body) && isString(body.token) ? body.token : "";
      const tokenHash = createHash("sha256").update(token).digest("base64url");
      const invite = state.invites.find((entry) => entry.token === token || entry.token === tokenHash);
      if (!invite || invite.revokedAt !== null) {
        sendError(res, 404, "invite_not_found", "Invitation not found.");
        return;
      }
      const host = state.hosts.find((entry) => entry.hostId === invite.hostId);
      if (!host) {
        sendError(res, 404, "host_not_found", "Host not found.");
        return;
      }
      sendJson(res, 200, {
        inviteId: invite.inviteId,
        hostId: host.hostId,
        hostName: host.name,
        role: invite.role,
        expiresAt: invite.expiresAt,
        emailBound: invite.email !== null,
        permanent: invite.permanent,
        devicePublicKey: host.devicePublicKey,
        keyHandovers: host.keyHandovers,
      });
      return;
    }

    // 7. Authenticated routes below
    const auth = readSessionFromRequest(req);
    if (!auth) {
      sendError(res, 401, "unauthorized", "Authentication required.");
      return;
    }
    const { session, user } = auth;

    if (method === "GET" && (pathname === "/v1/me" || pathname === "/v1/mobile-auth/session")) {
      sendJson(res, 200, formatUser(user));
      return;
    }

    if (method === "DELETE" && pathname === "/v1/mobile-auth/session") {
      state.sessions = state.sessions.filter((entry) => entry.sessionId !== session.sessionId);
      await persistState();
      sendEmpty(res, 204);
      return;
    }

    if (method === "PATCH" && pathname === "/v1/me/profile") {
      const body = await readJsonBody(req);
      if (isDynamicRecord(body) && (body.name === null || isString(body.name))) {
        user.name = body.name ? body.name.trim() : null;
        await persistState();
        broadcastToUser(user.id, { type: "account-profile-changed", version: SIGNAL_PROTOCOL_VERSION });
      }
      sendJson(res, 200, formatUser(user));
      return;
    }

    if (method === "PUT" && pathname === "/v1/me/analytics") {
      user.analyticsEnabled = false;
      sendJson(res, 200, formatUser(user));
      return;
    }

    if (method === "PUT" && pathname === "/v1/me/chat-color") {
      const body = await readJsonBody(req);
      const chatColor = isDynamicRecord(body) ? body.chatColor : null;
      user.chatColor = isAvatarColor(chatColor) ? chatColor : null;
      await persistState();
      broadcastToUser(user.id, { type: "account-profile-changed", version: SIGNAL_PROTOCOL_VERSION });
      sendJson(res, 200, formatUser(user));
      return;
    }

    if ((method === "PUT" || method === "DELETE") && pathname === "/v1/me/avatar") {
      if (method === "DELETE") {
        user.avatarBase64 = null;
        user.avatarMimeType = null;
        user.avatarVersion += 1;
      } else {
        const bytes = await readRawBody(req);
        user.avatarMimeType = req.headers["content-type"]?.split(";")[0]?.trim() || "image/png";
        user.avatarBase64 = bytes.toString("base64");
        user.avatarVersion += 1;
      }
      await persistState();
      broadcastToUser(user.id, { type: "account-profile-changed", version: SIGNAL_PROTOCOL_VERSION });
      sendJson(res, 200, formatUser(user));
      return;
    }

    // Mobile Connect ticket & link management
    if (method === "POST" && pathname === "/v1/mobile-auth/ticket") {
      const body = await readJsonBody(req);
      const host = isDynamicRecord(body) && isMobileConnectHostBinding(body.host) ? body.host : null;
      if (!host) {
        sendError(res, 400, "invalid_host", "Invalid Mobile Connect host binding.");
        return;
      }
      const ticket = randomBytes(32).toString("base64url");
      const expiresAt = Date.now() + MOBILE_TICKET_TTL_MS;
      mobileTickets.set(ticket, { ticket, userId: user.id, host, expiresAt });
      sendJson(res, 200, { ticket, expiresAt });
      return;
    }

    if (method === "DELETE" && pathname === "/v1/mobile-auth/ticket") {
      const hostId = url.searchParams.get("host");
      for (const [key, entry] of mobileTickets.entries()) {
        if (entry.userId === user.id && (!hostId || entry.host.hostId === hostId)) {
          mobileTickets.delete(key);
        }
      }
      sendEmpty(res, 204);
      return;
    }

    if (method === "POST" && pathname === "/v1/mobile-auth/link") {
      const body = await readJsonBody(req);
      const host = isDynamicRecord(body) && isMobileConnectHostBinding(body.host) ? body.host : null;
      if (!host) {
        sendError(res, 400, "invalid_host", "Invalid Mobile Connect host binding.");
        return;
      }
      state.mobileLinks = state.mobileLinks.filter(
        (entry) => !(entry.userId === user.id && entry.host.hostId === host.hostId),
      );
      const link: StoredMobileConnectLink = {
        userId: user.id,
        host,
        token: randomBytes(36).toString("base64url"),
        createdAt: Date.now(),
      };
      state.mobileLinks.push(link);
      await persistState();
      sendJson(res, 200, { link: link.token, createdAt: link.createdAt });
      return;
    }

    if (method === "DELETE" && pathname === "/v1/mobile-auth/link") {
      const hostId = url.searchParams.get("host");
      state.mobileLinks = state.mobileLinks.filter(
        (entry) => !(entry.userId === user.id && (!hostId || entry.host.hostId === hostId)),
      );
      await persistState();
      sendEmpty(res, 204);
      return;
    }

    if (method === "GET" && pathname === "/v1/mobile-auth/devices") {
      const includeDesktop = url.searchParams.get("includeDesktop") === "true";
      const userSessions = state.sessions.filter((entry) => entry.userId === user.id);
      if (includeDesktop) {
        sendJson(res, 200, {
          sessions: userSessions.map((entry) => ({
            sessionId: entry.sessionId,
            name: entry.name,
            kind: entry.kind,
            current: entry.sessionId === session.sessionId,
            connectedAt: entry.connectedAt,
            lastActiveAt: entry.lastActiveAt,
          })),
        });
        return;
      }
      const mobileDevices = userSessions
        .filter((entry) => entry.kind === "mobile")
        .map((entry) => ({
          sessionId: entry.sessionId,
          name: entry.name,
          platform: entry.platform,
          connectedAt: entry.connectedAt,
          lastActiveAt: entry.lastActiveAt,
          via: entry.via,
        }));
      sendJson(res, 200, { devices: mobileDevices });
      return;
    }

    const deviceRevokeMatch = /^\/v1\/mobile-auth\/devices\/([^/]+)$/u.exec(pathname);
    if (method === "DELETE" && deviceRevokeMatch) {
      const targetSessionId = decodeURIComponent(deviceRevokeMatch[1] ?? "");
      state.sessions = state.sessions.filter(
        (entry) => !(entry.userId === user.id && entry.sessionId === targetSessionId),
      );
      await persistState();
      sendEmpty(res, 204);
      return;
    }

    // Remote Hosts Registration & Directory
    if (method === "POST" && pathname === "/v2/remote/hosts/register") {
      const body = await readJsonBody(req);
      if (!isDynamicRecord(body) || !isString(body.hostId) || !isString(body.name) || !isString(body.ownerMembershipId)) {
        sendError(res, 400, "invalid_request", "Invalid host registration payload.");
        return;
      }
      const hostId = body.hostId;
      const name = body.name;
      const ownerMembershipId = body.ownerMembershipId;
      const devicePublicKey = isString(body.devicePublicKey) ? body.devicePublicKey : null;
      const rotateCredential = body.rotateCredential === true;
      const providedToken = isString(body.machineToken) ? body.machineToken : null;

      let host = state.hosts.find((entry) => entry.hostId.toLowerCase() === hostId.toLowerCase());
      const issuedToken = rotateCredential || !host ? randomBytes(32).toString("base64url") : null;
      const machineToken = issuedToken ?? providedToken ?? host?.machineToken ?? randomBytes(32).toString("base64url");

      if (!host) {
        host = {
          hostId,
          name,
          ownerUserId: user.id,
          ownerMembershipId,
          authEpoch: 1,
          machineToken,
          devicePublicKey,
          logoKey: null,
          logoMimeType: null,
          logoBase64: null,
          keyHandovers: [],
        };
        state.hosts.push(host);
      } else {
        host.name = name;
        host.ownerUserId = user.id;
        host.ownerMembershipId = ownerMembershipId;
        host.machineToken = machineToken;
        if (devicePublicKey !== null) host.devicePublicKey = devicePublicKey;
      }

      let membership = state.memberships.find(
        (entry) => entry.hostId.toLowerCase() === hostId.toLowerCase() && entry.userId === user.id,
      );
      if (!membership) {
        membership = {
          membershipId: ownerMembershipId,
          hostId: host.hostId,
          userId: user.id,
          role: "owner",
          status: "active",
          createdAt: Date.now(),
        };
        state.memberships.push(membership);
      } else {
        membership.membershipId = ownerMembershipId;
        membership.role = "owner";
        membership.status = "active";
      }

      await persistState();
      broadcastToUser(user.id, { type: "account-servers-changed", version: SIGNAL_PROTOCOL_VERSION });

      sendJson(res, 200, {
        hostId: host.hostId,
        name: host.name,
        membershipId: membership.membershipId,
        authEpoch: host.authEpoch,
        machineToken: issuedToken ?? host.machineToken,
      });
      return;
    }

    if (method === "GET" && pathname === "/v2/remote/hosts/") {
      const hosts = state.hosts.map((host) => {
        const membership = state.memberships.find(
          (entry) =>
            entry.hostId.toLowerCase() === host.hostId.toLowerCase() &&
            entry.userId === user.id &&
            entry.status === "active",
        );
        return {
          hostId: host.hostId,
          name: host.name,
          logoKey: host.logoKey,
          devicePublicKey: host.devicePublicKey,
          keyHandovers: host.keyHandovers,
          authEpoch: host.authEpoch,
          membershipId: membership?.membershipId ?? host.ownerMembershipId,
          role: membership?.role ?? "owner",
          memberLimit: 100,
          hosted: false,
        };
      });
      sendJson(res, 200, { hosts });
      return;
    }

    const hostDeleteMatch = /^\/v2\/remote\/hosts\/([^/]+)\/$/u.exec(pathname);
    if (method === "DELETE" && hostDeleteMatch) {
      const hostId = decodeURIComponent(hostDeleteMatch[1] ?? "");
      state.hosts = state.hosts.filter((entry) => entry.hostId.toLowerCase() !== hostId.toLowerCase());
      state.memberships = state.memberships.filter((entry) => entry.hostId.toLowerCase() !== hostId.toLowerCase());
      await persistState();
      broadcastToUser(user.id, { type: "account-servers-changed", version: SIGNAL_PROTOCOL_VERSION });
      sendEmpty(res, 204);
      return;
    }

    const hostLogoMatch = /^\/v2\/remote\/hosts\/([^/]+)\/logo$/u.exec(pathname);
    if (hostLogoMatch) {
      const hostId = decodeURIComponent(hostLogoMatch[1] ?? "");
      const host = state.hosts.find((entry) => entry.hostId.toLowerCase() === hostId.toLowerCase());
      if (!host) {
        sendError(res, 404, "host_not_found", "Host not found.");
        return;
      }
      if (method === "DELETE") {
        host.logoKey = null;
        host.logoMimeType = null;
        host.logoBase64 = null;
        await persistState();
        sendEmpty(res, 204);
        return;
      }
      if (method === "PUT") {
        const bytes = await readRawBody(req);
        host.logoMimeType = req.headers["content-type"]?.split(";")[0]?.trim() || "image/png";
        host.logoBase64 = bytes.toString("base64");
        host.logoKey = req.headers["openbot-logo-version"]?.toString() || randomUUID();
        await persistState();
        sendJson(res, 200, { logoKey: host.logoKey });
        return;
      }
      if (method === "GET") {
        if (!host.logoBase64 || !host.logoMimeType) {
          sendError(res, 404, "not_found", "Host logo not found.");
          return;
        }
        const bytes = Buffer.from(host.logoBase64, "base64");
        res.writeHead(200, {
          "Content-Type": host.logoMimeType,
          "Content-Length": String(bytes.byteLength),
        });
        res.end(bytes);
        return;
      }
    }

    // Remote Members & Invites
    const hostMembersMatch = /^\/v2\/remote\/hosts\/([^/]+)\/members\/$/u.exec(pathname);
    if (method === "GET" && hostMembersMatch) {
      const hostId = decodeURIComponent(hostMembersMatch[1] ?? "");
      const members = state.memberships
        .filter((entry) => entry.hostId.toLowerCase() === hostId.toLowerCase())
        .map((entry) => {
          const memberUser = state.users.find((candidate) => candidate.id === entry.userId) ?? user;
          const formatted = formatUser(memberUser);
          return {
            membershipId: entry.membershipId,
            email: formatted.email,
            name: formatted.name,
            avatarUrl: formatted.avatarUrl,
            ...(formatted.chatColor ? { chatColor: formatted.chatColor } : {}),
            role: entry.role,
            status: entry.status,
            createdAt: entry.createdAt,
          };
        });
      sendJson(res, 200, { members });
      return;
    }

    const hostMemberUpdateMatch = /^\/v2\/remote\/hosts\/([^/]+)\/members\/([^/]+)$/u.exec(pathname);
    if (hostMemberUpdateMatch) {
      const hostId = decodeURIComponent(hostMemberUpdateMatch[1] ?? "");
      const membershipId = decodeURIComponent(hostMemberUpdateMatch[2] ?? "");
      const membership = state.memberships.find(
        (entry) => entry.hostId.toLowerCase() === hostId.toLowerCase() && entry.membershipId === membershipId,
      );
      if (method === "PATCH" && membership) {
        const body = await readJsonBody(req);
        if (isDynamicRecord(body) && (body.role === "admin" || body.role === "member")) {
          membership.role = body.role;
        }
        if (isDynamicRecord(body) && body.reactivate === true) {
          membership.status = "active";
        }
        await persistState();
      } else if (method === "DELETE" && membership) {
        membership.status = "revoked";
        await persistState();
      }
      sendEmpty(res, 204);
      return;
    }

    const hostInvitesMatch = /^\/v2\/remote\/hosts\/([^/]+)\/invites$/u.exec(pathname);
    if (hostInvitesMatch) {
      const hostId = decodeURIComponent(hostInvitesMatch[1] ?? "");
      if (method === "GET") {
        const invites = state.invites.filter((entry) => entry.hostId.toLowerCase() === hostId.toLowerCase());
        sendJson(res, 200, { invites });
        return;
      }
      if (method === "POST") {
        const body = await readJsonBody(req);
        const role = isDynamicRecord(body) && body.role === "admin" ? "admin" : "member";
        const email = isDynamicRecord(body) && isString(body.email) ? body.email.trim().toLowerCase() : null;
        const permanent = isDynamicRecord(body) && isBoolean(body.permanent) ? body.permanent : false;
        const token = randomBytes(32).toString("base64url");
        const invite: StoredRemoteInvite = {
          inviteId: randomUUID(),
          token,
          hostId,
          email,
          role,
          expiresAt: permanent ? 0 : Date.now() + 7 * 24 * 60 * 60 * 1_000,
          usedAt: null,
          revokedAt: null,
          permanent,
          useCount: 0,
        };
        state.invites.push(invite);
        await persistState();
        sendJson(res, 200, {
          inviteId: invite.inviteId,
          token: invite.token,
          expiresAt: invite.expiresAt,
          permanent: invite.permanent,
          useCount: invite.useCount,
        });
        return;
      }
    }

    if (method === "POST" && pathname === "/v2/remote/invites/accept") {
      const body = await readJsonBody(req);
      const token = isDynamicRecord(body) && isString(body.token) ? body.token : "";
      const invite = state.invites.find((entry) => entry.token === token && entry.revokedAt === null);
      if (!invite) {
        sendError(res, 404, "invite_not_found", "Invitation not found.");
        return;
      }
      invite.usedAt = Date.now();
      invite.useCount += 1;
      let membership = state.memberships.find(
        (entry) => entry.hostId.toLowerCase() === invite.hostId.toLowerCase() && entry.userId === user.id,
      );
      if (!membership) {
        membership = {
          membershipId: randomUUID(),
          hostId: invite.hostId,
          userId: user.id,
          role: invite.role,
          status: "active",
          createdAt: Date.now(),
        };
        state.memberships.push(membership);
      } else {
        membership.status = "active";
      }
      await persistState();
      sendJson(res, 200, {
        hostId: invite.hostId,
        membershipId: membership.membershipId,
        role: invite.role,
      });
      return;
    }

    const inviteDeleteMatch = /^\/v2\/remote\/invites\/([^/]+)$/u.exec(pathname);
    if (method === "DELETE" && inviteDeleteMatch) {
      const inviteId = decodeURIComponent(inviteDeleteMatch[1] ?? "");
      const invite = state.invites.find((entry) => entry.inviteId === inviteId);
      if (invite) {
        invite.revokedAt = Date.now();
        await persistState();
      }
      sendEmpty(res, 204);
      return;
    }

    // Remote Sessions (Client WebRTC bootstrap)
    if (method === "POST" && pathname === "/v2/remote/sessions/") {
      const body = await readJsonBody(req);
      const hostId = isDynamicRecord(body) && isString(body.hostId) ? body.hostId : "";
      const host = state.hosts.find((entry) => entry.hostId.toLowerCase() === hostId.toLowerCase());
      if (!host) {
        sendError(res, 404, "host_not_found", "Host is not registered.");
        return;
      }
      const membership = state.memberships.find(
        (entry) =>
          entry.hostId.toLowerCase() === host.hostId.toLowerCase() &&
          entry.userId === user.id &&
          entry.status === "active",
      );
      const sessionRecord: ActiveRemoteSession = {
        sessionId: randomUUID(),
        hostId: host.hostId,
        userId: user.id,
        membershipId: membership?.membershipId ?? host.ownerMembershipId,
        role: membership?.role ?? "owner",
        authEpoch: host.authEpoch,
        expiresAt: Date.now() + SESSION_TTL_MS,
      };
      remoteSessions.set(sessionRecord.sessionId, sessionRecord);
      sendJson(res, 200, {
        sessionId: sessionRecord.sessionId,
        hostId: sessionRecord.hostId,
        expiresAt: sessionRecord.expiresAt,
      });
      return;
    }

    const sessionTicketMatch = /^\/v2\/remote\/sessions\/([^/]+)\/ticket$/u.exec(pathname);
    if (method === "POST" && sessionTicketMatch) {
      const sessionId = decodeURIComponent(sessionTicketMatch[1] ?? "");
      const body = await readJsonBody(req);
      const clientPublicKey = isDynamicRecord(body) && isString(body.clientPublicKey) ? body.clientPublicKey : "";
      if (!clientPublicKey) {
        sendError(res, 400, "invalid_request", "Missing clientPublicKey.");
        return;
      }
      let remoteSession = remoteSessions.get(sessionId);
      if (!remoteSession) {
        const defaultHost = state.hosts[0];
        if (!defaultHost) {
          sendError(res, 404, "session_inactive", "Remote session not found.");
          return;
        }
        remoteSession = {
          sessionId,
          hostId: defaultHost.hostId,
          userId: user.id,
          membershipId: defaultHost.ownerMembershipId,
          role: "owner",
          authEpoch: defaultHost.authEpoch,
          expiresAt: Date.now() + SESSION_TTL_MS,
        };
        remoteSessions.set(sessionId, remoteSession);
      }
      const host = state.hosts.find((entry) => entry.hostId.toLowerCase() === remoteSession.hostId.toLowerCase());
      if (!host) {
        sendError(res, 404, "host_not_found", "Host not found.");
        return;
      }
      const signed = await signSignalJwt({
        kind: "ticket",
        peer: "client",
        sessionId: remoteSession.sessionId,
        hostId: host.hostId,
        userId: remoteSession.userId,
        membershipId: remoteSession.membershipId,
        role: remoteSession.role,
        authEpoch: host.authEpoch,
        sessionExpiresAt: Math.floor(remoteSession.expiresAt / 1_000),
        clientPublicKey,
      });
      sendJson(res, 200, {
        ticket: signed.token,
        expiresAt: signed.expiresAt,
        signalUrl: signalUrlForRequest(req),
      });
      return;
    }

    const sessionEndMatch = /^\/v2\/remote\/sessions\/([^/]+)\/end$/u.exec(pathname);
    if (method === "POST" && sessionEndMatch) {
      const sessionId = decodeURIComponent(sessionEndMatch[1] ?? "");
      remoteSessions.delete(sessionId);
      sendEmpty(res, 204);
      return;
    }

    // Team auth tickets
    if (method === "POST" && pathname === "/v1/team-auth/ticket") {
      sendJson(res, 200, {
        ticket: randomBytes(24).toString("base64url"),
        expiresAt: Date.now() + 5 * 60 * 1_000,
      });
      return;
    }

    if (method === "POST" && pathname === "/v1/team-auth/redeem") {
      sendJson(res, 200, formatUser(user));
      return;
    }

    // Local stub responses for optional cloud features (Billing, License, Hosted Servers, Sites, Marketplace, SSO)
    if (method === "GET" && pathname === "/v1/me/billing/") {
      sendJson(res, 200, { available: false, hasCustomer: false, servers: [] });
      return;
    }
    if (method === "GET" && pathname === "/v1/me/license/") {
      sendJson(res, 200, {
        available: false,
        currency: null,
        license: null,
        used: 0,
        users: [],
        coveredBy: [],
      });
      return;
    }
    if (method === "GET" && pathname === "/v2/hosting/servers/") {
      sendJson(res, 200, { available: false, lifecycleAvailable: false, servers: [], maxServers: 0 });
      return;
    }
    if (method === "GET" && pathname === "/v2/hosting/plans") {
      sendJson(res, 200, { plans: [] });
      return;
    }
    if (method === "GET" && pathname.startsWith("/v1/sites/")) {
      sendJson(res, 200, { sites: [], limit: 0, used: 0 });
      return;
    }
    if (method === "GET" && pathname === "/v1/marketplace/agents/") {
      sendJson(res, 200, { agents: [], nextCursor: null });
      return;
    }
    if (method === "GET" && pathname === "/v1/marketplace/agents/mine") {
      sendJson(res, 200, { submissions: [] });
      return;
    }
    if (method === "GET" && pathname === "/v1/agent-templates/mine") {
      sendJson(res, 200, { templates: [] });
      return;
    }
    if (method === "GET" && pathname === "/v1/skills/") {
      sendJson(res, 200, { skills: [], nextCursor: null });
      return;
    }
    if (method === "GET" && pathname === "/v1/skills/mine") {
      sendJson(res, 200, { submissions: [] });
      return;
    }
    if (pathname.endsWith("/company-sign-in") && method === "GET") {
      sendJson(res, 200, {
        redirectUri: `http://127.0.0.1:${boundPort}/v1/auth/company/callback`,
        scimUrl: `http://127.0.0.1:${boundPort}/scim/v2`,
        domainRecord: { name: "_openbot-challenge", value: "local" },
        domainCheck: false,
        connection: null,
      });
      return;
    }

    sendError(res, 404, "not_found", `Local cloud route not found: ${method} ${pathname}`);
  };

  boundPort = await listenWithFallback(server, preferredPort);

  return {
    port: boundPort,
    localApiUrl: `http://127.0.0.1:${boundPort}`,
    resolveMobileConnectApiUrl: () => `http://${resolveReachableLocalHost(env)}:${boundPort}`,
    close: async () => {
      for (const client of wss.clients) {
        client.terminate();
      }
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await saveChain;
    },
  };
}

async function listenWithFallback(server: ReturnType<typeof createServer>, preferredPort: number): Promise<number> {
  const tryListen = (port: number) =>
    new Promise<number>((resolve, reject) => {
      const onError = (error: NodeJS.ErrnoException) => {
        server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        server.off("error", onError);
        const address = server.address();
        const actualPort = typeof address === "object" && address ? address.port : port;
        resolve(actualPort);
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(port, "0.0.0.0");
    });

  try {
    return await tryListen(preferredPort);
  } catch (error) {
    if (isDynamicRecord(error) && error.code === "EADDRINUSE") {
      logger.warn(`Port ${preferredPort} is in use; falling back to an available local port.`);
      return await tryListen(0);
    }
    throw error;
  }
}

async function loadOrCreatePersistedState(storagePath: string): Promise<{
  state: PersistedLocalCloudState;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  try {
    const raw = await readFile(storagePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedLocalCloudState;
    if (
      isDynamicRecord(parsed) &&
      parsed.version === 1 &&
      isString(parsed.keyId) &&
      isDynamicRecord(parsed.publicJwk) &&
      isDynamicRecord(parsed.privateJwk)
    ) {
      const privateKey = (await importJWK(parsed.privateJwk as JWK, "ES256")) as CryptoKey;
      const publicKey = (await importJWK(parsed.publicJwk as JWK, "ES256")) as CryptoKey;
      return {
        state: {
          version: 1,
          keyId: parsed.keyId,
          publicJwk: parsed.publicJwk as JWK,
          privateJwk: parsed.privateJwk as JWK,
          users: Array.isArray(parsed.users) ? parsed.users : [],
          sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
          hosts: Array.isArray(parsed.hosts) ? parsed.hosts : [],
          memberships: Array.isArray(parsed.memberships) ? parsed.memberships : [],
          invites: Array.isArray(parsed.invites) ? parsed.invites : [],
          mobileLinks: Array.isArray(parsed.mobileLinks) ? parsed.mobileLinks : [],
        },
        privateKey,
        publicKey,
      };
    }
  } catch {
    // Missing or invalid state file: generate a fresh one below.
  }

  const keyId = "local-cloud-key-1";
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = {
    ...(await exportJWK(publicKey)),
    kid: keyId,
    use: "sig",
    alg: "ES256",
  };
  const privateJwk = {
    ...(await exportJWK(privateKey)),
    kid: keyId,
    use: "sig",
    alg: "ES256",
  };

  const state: PersistedLocalCloudState = {
    version: 1,
    keyId,
    publicJwk,
    privateJwk,
    users: [],
    sessions: [],
    hosts: [],
    memberships: [],
    invites: [],
    mobileLinks: [],
  };

  try {
    await mkdir(dirname(storagePath), { recursive: true });
    await writeFile(storagePath, JSON.stringify(state, null, 2), { mode: 0o600 });
  } catch (error) {
    logger.warn("Could not write initial embedded local cloud state.", toLogValue(error));
  }

  return { state, privateKey, publicKey };
}

async function readRawBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const raw = await readRawBody(req);
  if (raw.byteLength === 0) return {};
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    return {};
  }
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": String(Buffer.byteLength(body)),
  });
  res.end(body);
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status);
  res.end();
}

function sendError(res: ServerResponse, status: number, code: string, message: string): void {
  sendJson(res, status, { error: { code, message } });
}
