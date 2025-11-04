import { IsEmail, IsString, MinLength, IsOptional } from "class-validator";

export class CreateUserDto {
  @IsString()
  @MinLength(3)
  firstName: string;

  @IsString()
  @MinLength(3)
  lastName: string;

  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  @MinLength(8)
  password?: string;

   @IsOptional()
  @IsString()
  googleId?: string;

   @IsOptional()
  @IsString()
  provider?: string;

    @IsOptional()
  @IsString()
  profilePicture?: string;
}
