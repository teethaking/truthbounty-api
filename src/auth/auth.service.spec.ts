import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';

jest.mock('ethers', () => ({
  verifyMessage: jest.fn(),
}));

import { verifyMessage } from 'ethers';

describe('AuthService Nonce behaviour', () => {
  let authService: AuthService;
  let jwtService: Partial<JwtService>;
  let prisma: Partial<PrismaService>;

  beforeEach(() => {
    jwtService = {
      sign: jest.fn().mockReturnValue('signed-token'),
    };

    prisma = {
      wallet: {
        findFirst: jest.fn().mockResolvedValue(null),
      } as any,
    } as Partial<PrismaService>;

    authService = new AuthService(prisma as PrismaService, jwtService as JwtService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('generates a challenge and stores NonceRecord with camelCase fields', () => {
    const address = '0xAbCd';
    const message = authService.generateChallenge(address);
    expect(typeof message).toBe('string');

    const record = (authService as any).nonces.get(address.toLowerCase());
    expect(record).toBeDefined();
    expect(record.nonce).toBeDefined();
    expect(record.createdAt).toBeDefined();
    expect(typeof record.nonce).toBe('string');
    expect(typeof record.createdAt).toBe('number');
  });

  it('cleans up expired nonces (cleanupNonces removes old createdAt entries)', () => {
    const address = '0xdead';
    authService.generateChallenge(address);
    const map = (authService as any).nonces;
    const record = map.get(address.toLowerCase());
    // simulate expiry by setting createdAt far in the past
    record.createdAt = Date.now() - ((authService as any).NONCE_TTL + 1000);

    // call private cleanup
    (authService as any).cleanupNonces();
    expect(map.has(address.toLowerCase())).toBe(false);
  });

  it('allows login and deletes nonce (single-use) and is case-insensitive', async () => {
    const address = '0xAaBbCc';
    const lower = address.toLowerCase();

    // generate challenge
    const challenge = authService.generateChallenge(address);
    const record = (authService as any).nonces.get(lower);
    const nonce = record.nonce;

    // Prepare login DTO
    const message = `Sign in to TruthBounty: ${nonce}`;
    const signature = '0xsig';

    // mock verifyMessage to return mixed-case recovered address
    (verifyMessage as jest.Mock).mockReturnValue(address);

    // call login
    const result = await authService.login({ address: lower, signature, message } as any);
    expect(result).toBeDefined();
    expect(result.accessToken).toBe('signed-token');

    // ensure nonce deleted (single-use)
    expect((authService as any).nonces.has(lower)).toBe(false);
  });
});
