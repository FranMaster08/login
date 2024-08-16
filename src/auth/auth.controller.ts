import {
  Controller,
  Post,
  Body,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Post('token')
  async generateToken(@Body() createAuthDto: CreateAuthDto) {
    const { apikey, secret, payload } = createAuthDto;

    try {
      const token = await this.authService.generacionToken(
        apikey,
        secret,
        payload,
      );

      if (token) {
        return { token };
      } else {
        throw new HttpException(
          'API key or secret is invalid',
          HttpStatus.UNAUTHORIZED,
        );
      }
    } catch (error) {
      this.logger.error('Error generating token:', error.message);
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
