import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { DatabaseService } from 'src/database/database.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Prisma, User } from 'generated/prisma/client';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: DatabaseService) {}

  async findUserByEmail(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    return user;
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const {
      firstName,
      lastName,
      email,
      password,
      googleId,
      provider,
      profilePicture,
    } = createUserDto;
    const existingUser = await this.findUserByEmail(email);
    if (existingUser) {
      return existingUser;
    }
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const hash = crypto.createHash('sha256').update(email).digest('hex');
      const accountNumber = BigInt('0x' + hash)
        .toString()
        .slice(0, 10);
      const data = {
        firstName,
        lastName,
        email,
        password: hashedPassword,
        googleId,
        provider: provider || 'local',
        profilePicture,
        accountNumber,
      };
      const user = await this.prisma.user.create({ data });
      return user;
    } catch (error) {
      throw new InternalServerErrorException('Failed to create user', error);
    }
  }

  async findAll() {
    const users = await this.prisma.user.findMany();
    return users;
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  async update(
    id: number,
    data: Partial<{
      email: string;
      password: string;
      firstName?: string;
      lastName?: string;
      refreshToken?: string;
      expiresRefreshToken?: Date;
      accessToken?: string;
      expiresAccessToken?: Date;
    }>,
  ) {
    return this.prisma.user.update({
      where: { id },
      data,
    });
  }

  async remove(id: number) {
    try {
      await this.prisma.user.delete({
        where: { id: Number(id) },
      });
      return { message: 'User deleted successfully' };
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2025'
      ) {
        throw new NotFoundException('User not found');
      }
      console.error('Error deleting user:', error);
      throw error;
    }
  }
}
