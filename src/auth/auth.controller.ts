import {
  Controller,
  Post,
  UseGuards,
  Get,
  Body,
  Query,
  HttpCode,
  Request,
  HttpStatus,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { PassportLocalGuard } from './guards/local.guard';
import { JwtAuthGuard } from './guards/jwt.guard';
import { PassportGoogleGuard } from './guards/passport-google.guard';
import { Response } from 'express';
import { LoginResponseDto } from '../users/dto/login-response.dto';
import { AuthRequest } from './auth.types';
import { SignInDto } from 'src/users/dto/signin-request.dto';
import { CurrentUser } from '../decorators/current-user.decorator';
import { JwtRefreshAuthGuard } from './guards/jwt-refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  @UseGuards(PassportLocalGuard)
  async login(
    @CurrentUser() user: SignInDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.signIn(user, response);
    return user;
  }

  @Post('refresh')
  @UseGuards(JwtRefreshAuthGuard)
  async refreshToken(
    @CurrentUser() user: SignInDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.signIn(user, response);
    return user;
  }

  @Get('google')
  @UseGuards(PassportGoogleGuard)
  async googleLogin() {}


  @Get('google/callback')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PassportGoogleGuard)
  async googleCallback(
    @CurrentUser() user: SignInDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.googleSignIn(user, response);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@Res({ passthrough: true }) response: Response) {
    await this.authService.logout(response);
    return { message: 'User successfully logged out' };
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Request() req: AuthRequest) {
    const email = req.user.email;
    const userProfile = await this.authService.getProfile(email);
    return userProfile;
  }
}
