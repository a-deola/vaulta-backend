import { IsEmail, IsNotEmpty, IsNumber, IsString } from 'class-validator';


export class LoginResponseDto {
  @IsNotEmpty()
  @IsNumber()
  id: number;

  @IsEmail()
  email: string;
}
