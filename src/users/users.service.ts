import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { DatabaseService } from 'src/database/database.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: DatabaseService) {}

  async create(createUserDto: CreateUserDto) {
    const { firstName, lastName, email, password } = createUserDto;
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      throw new ConflictException('Email already in use');
    }
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const hash = crypto.createHash('sha256').update(email).digest('hex');
      const accountNumber = BigInt('0x' + hash)
        .toString()
        .slice(0, 10);
      const user = await this.prisma.user.create({
        data: {
          firstName,
          lastName,
          email,
          password: hashedPassword,
          accountNumber,
        },
      });
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

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  async remove(id: number) {
    try {
      await this.prisma.user.delete({
        where: { id: Number(id) },
      });
      return { message: 'User deleted successfully' };
    } catch (error) {
      console.error('Error deleting user:', error);
    }
  }
}
