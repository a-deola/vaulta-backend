import { IsEmail, IsString } from 'class-validator';

export class AuthInputDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}
