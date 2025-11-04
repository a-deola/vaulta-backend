import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/local.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { DatabaseService } from 'src/database/database.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  providers: [
    AuthService,
    LocalStrategy,
    GoogleStrategy,
    JwtStrategy,
    JwtRefreshStrategy,
    DatabaseService
  ],
  controllers: [AuthController],
  imports: [PassportModule, UsersModule, JwtModule, ConfigModule],
})
export class AuthModule {}
