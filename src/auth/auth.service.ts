import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { GoogleData } from './auth.types';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { LoginResponseDto } from '../users/dto/login-response.dto';
import { SignInDto } from 'src/users/dto/signin-request.dto';
import { AuthInputDto } from '../users/dto/auth-input.dto';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from 'src/database/database.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private readonly prisma: DatabaseService,
  ) {}

  private async generateLoginTokens(user: SignInDto): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresAccessToken: Date;
    expiresRefreshToken: Date;
  }> {
    const tokenPayload = {
      sub: user.id,
      email: user.email,
    };

    const expiresAccessToken = new Date();
    expiresAccessToken.setMinutes(
      expiresAccessToken.getMinutes() +
        parseInt(
          this.configService.getOrThrow<string>('JWT_ACCESS_EXPIRES_IN'),
        ),
    );

    const expiresRefreshToken = new Date();
    expiresRefreshToken.setMinutes(
      expiresRefreshToken.getMinutes() +
        parseInt(
          this.configService.getOrThrow<string>('REFRESH_TOKEN_EXPIRES_IN'),
        ),
    );

    const accessToken = await this.jwtService.signAsync(tokenPayload, {
      secret: this.configService.getOrThrow<string>('JWT_ACCESS_SECRET'),
      expiresIn:
        parseInt(
          this.configService.getOrThrow<string>('JWT_ACCESS_EXPIRES_IN'),
        ) * 60,
    });

    const refreshToken = await this.jwtService.signAsync(tokenPayload, {
      secret: this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET'),
      expiresIn:
        parseInt(
          this.configService.getOrThrow<string>('REFRESH_TOKEN_EXPIRES_IN'),
        ) * 60,
    });
    return {
      accessToken,
      refreshToken,
      expiresAccessToken,
      expiresRefreshToken,
    };
  }

  private setAuthCookies(
    response: Response,
    tokens: {
      accessToken: string;
      refreshToken: string;
      expiresAccessToken: Date;
      expiresRefreshToken: Date;
    },
  ): void {
    response.cookie('Authentication', tokens.accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'none',
      expires: tokens.expiresAccessToken,
    });

    response.cookie('Refresh', tokens.refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'none',
      expires: tokens.expiresRefreshToken,
    });
  }

  async validateUser({ email, password }: AuthInputDto): Promise<SignInDto> {
    try {
      const user = await this.usersService.findUserByEmail(email);
      if (!user) {
        throw new NotFoundException('User not found');
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException('Password is incorrect');
      }
      return {
        id: user.id,
        email: user.email,
      };
    } catch (error) {
      throw error;
    }
  }

  async signIn(user: SignInDto, response: Response): Promise<LoginResponseDto> {
    const { id } = user;
    const foundUser = await this.prisma.user.findUnique({
      where: { id },
    });
    const loginTokens = await this.generateLoginTokens(user);
    const {
      accessToken,
      refreshToken,
      expiresAccessToken,
      expiresRefreshToken,
    } = loginTokens;

    await this.usersService.update(user.id, {
      refreshToken: await bcrypt.hash(refreshToken, 10),
      expiresRefreshToken: expiresRefreshToken,
    });
    this.setAuthCookies(response, {
      accessToken,
      refreshToken,
      expiresAccessToken,
      expiresRefreshToken,
    });

    return {
      id: foundUser.id,
      email: foundUser.email,
    };
  }

  async verifyRefreshToken(refreshToken: string, email: string) {
    try {
      const user = await this.usersService.findUserByEmail(email);
      const authenticated = await bcrypt.compare(
        refreshToken,
        user.refreshToken,
      );
      if (!authenticated) {
        throw new UnauthorizedException("No refresh token found");
      }
      return user;
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async validateGoogleUser(profile: GoogleData) {
    const existingUser = await this.usersService.findUserByEmail(profile.email);
    try{
    if (existingUser) {
      if (!existingUser.googleId) {
        await this.usersService.update(existingUser.id, {
          googleId: profile.googleId,
          provider: 'google',
          profilePicture: profile.avatar,
        } as Partial<CreateUserDto>);
      }
      return existingUser;
    }
    const newUser = await this.usersService.create({
      googleId: profile.googleId,
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
      profilePicture: profile.avatar,
      provider: 'google',
    });
    return newUser;
  }catch (error){
    console.error(error)
  }
  }

  async googleSignIn(user, response: Response): Promise<void> {
    const loginTokens = await this.generateLoginTokens(user);
    const {
      accessToken,
      refreshToken,
      expiresAccessToken,
      expiresRefreshToken,
    } = loginTokens;
    await this.usersService.update(user.id, {
      refreshToken: await bcrypt.hash(refreshToken, 10),
      expiresRefreshToken: expiresRefreshToken,
    });
    this.setAuthCookies(response, {
      accessToken,
      refreshToken,
      expiresAccessToken,
      expiresRefreshToken,
    });
    response.redirect('http://localhost:5173/dashboard');
  }

  async logout(response: Response): Promise<void> {
    response.clearCookie('Refresh', {
      httpOnly: true,
      sameSite: 'none',
      secure: this.configService.get('NODE_ENV') === 'production',
    });
    response.clearCookie('Authentication', {
      httpOnly: true,
      sameSite: 'none',
      secure: this.configService.get('NODE_ENV') === 'production',
    });
    return;
  }
  async getProfile(email: string) {
    return this.usersService.findUserByEmail(email);
  }
}
