import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { verifyMessage } from 'ethers';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';

export interface NonceRecord {
  nonce: string;
  createdAt: number;
}

@Injectable()
export class AuthService {
  private nonces = new Map<string, NonceRecord>();
  private readonly NONCE_TTL = 5 * 60 * 1000; // 5 minutes

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {
    // Clean up expired nonces every minute
    setInterval(() => this.cleanupNonces(), 60 * 1000);
  }

  /**
   * Generate a nonce challenge for a wallet address
   */
  generateChallenge(address: string): string {
    const nonce = this.generateRandomNonce();
    this.nonces.set(address.toLowerCase(), {
      nonce,
      createdAt: Date.now(),
    });

    return `Sign in to TruthBounty: ${nonce}`;
  }

  /**
   * Verify wallet signature and issue JWT token
   */
  async login(loginDto: LoginDto): Promise<{ accessToken: string; user: any }> {
    const { address, signature, message } = loginDto;

    // 1. Verify the signature
    let recoveredAddress: string;
    try {
      recoveredAddress = verifyMessage(message, signature);
    } catch (error) {
      throw new BadRequestException('Invalid signature format');
    }

    // 2. Check if recovered address matches the claimed address
    if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
      throw new UnauthorizedException('Signature verification failed. Address mismatch.');
    }

    // 3. Verify the message contains a valid nonce
    const nonceRecord = this.nonces.get(address.toLowerCase());
    if (!nonceRecord) {
      throw new UnauthorizedException('No challenge found. Please request a challenge first.');
    }

    // 4. Check if nonce has expired
    if (Date.now() - nonceRecord.createdAt > this.NONCE_TTL) {
      this.nonces.delete(address.toLowerCase());
      throw new UnauthorizedException('Challenge expired. Please request a new challenge.');
    }

    // 5. Verify the message contains the correct nonce
    if (!message.includes(nonceRecord.nonce)) {
      throw new UnauthorizedException('Invalid nonce in message.');
    }

    // 6. Delete used nonce (prevent replay attacks)
    this.nonces.delete(address.toLowerCase());

    // 7. Find or create user
    let user = await this.prisma.wallet.findFirst({
      where: { address: address.toLowerCase() },
      include: { user: true },
    });

    // If wallet doesn't exist, we can still allow login but user won't have full access
    // until they link their wallet properly
    const userId = user?.user?.id || null;

    // 8. Generate JWT token
    const payload = {
      address: address.toLowerCase(),
      userId,
      sub: address.toLowerCase(),
    };

    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: {
        id: userId,
        address: address.toLowerCase(),
      },
    };
  }

  /**
   * Validate JWT token and return user info
   */
  async validateToken(payload: any): Promise<any> {
    const { address, userId } = payload;

    // Verify wallet still exists
    const wallet = await this.prisma.wallet.findFirst({
      where: { address },
      include: { user: true },
    });

    return {
      address,
      userId: wallet?.user?.id || userId,
      user: wallet?.user || null,
    };
  }

  /**
   * Generate a random nonce
   */
  private generateRandomNonce(): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = 32;
    let nonce = '';

    // Use crypto for secure random generation
    const crypto = require('crypto');
    const bytes = crypto.randomBytes(length);

    for (let i = 0; i < length; i++) {
      nonce += characters[bytes[i] % characters.length];
    }

    return nonce;
  }

  /**
   * Clean up expired nonces
   */
  private cleanupNonces(): void {
    const now = Date.now();
    for (const [address, record] of this.nonces.entries()) {
      if (now - record.createdAt > this.NONCE_TTL) {
        this.nonces.delete(address);
      }
    }
  }
}
