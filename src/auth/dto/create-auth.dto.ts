import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsObject } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateAuthDto {
  @ApiProperty({
    example: 'front-login-key',
    description: 'API key asociada al cliente o aplicación',
  })
  @IsString()
  @IsNotEmpty()
  readonly apikey: string;

  @ApiProperty({
    example: 'front-login-secret',
    description: 'Secreto asociado a la API key que debe coincidir con el hash almacenado',
  })
  @IsString()
  @IsNotEmpty()
  readonly secret: string;

  @ApiProperty({
    example: { userId: 123, role: 'admin' },
    description: 'Payload que se incluirá en el token',
  })
  @IsObject()
  @Type(() => Object)
  readonly payload: object;
}
