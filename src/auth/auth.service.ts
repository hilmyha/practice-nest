import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async register(dto: AuthDto) {
    const { email, password } = dto;

    // Check if user already exists
    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (foundUser) {
      throw new BadRequestException('User already exists');
    }

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Create user
    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    // Return message
    return { message: 'register success' };
  }

  async login(dto: AuthDto) {
    const { email, password } = dto;

    // Check if user exists
    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!foundUser) {
      throw new BadRequestException('Invalid credentials');
    }

    // Compare password
    const isMatch = await this.comparePassword({
      password,
      hash: foundUser.hashedPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Invalid credentials');
    }

    // sign jwt and return user

    return { message: 'login success' };
  }

  async logout() {
    return '';
  }

  // Hash password helper
  async hashPassword(password: string) {
    const saltOrRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltOrRounds);

    return hashedPassword;
  }

  // Compare password helper
  async comparePassword(args: { password: string; hash: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }
}
