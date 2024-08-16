import { Injectable, Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcryptjs';
import * as fs from 'fs';
import * as path from 'path';
import { CreateAuthDto } from './dto/create-auth.dto';

interface ApiKey {
  id: number;
  name: string;
  tipoToken: {
    id: number;
    name: string;
  };
  apikey: string;
  secretHash: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly apiKeys: ApiKey[];

  constructor() {
    this.apiKeys = this.loadApiKeys();
  }

  private loadApiKeys(): ApiKey[] {
    try {
      const filePath = path.resolve(__dirname, 'apikeys.json');
      const data = fs.readFileSync(filePath, 'utf8');
      this.logger.log('API keys loaded successfully.');
      return JSON.parse(data)
    } catch (error) {
      // this.logger.error('Error loading API keys:', error.message);
      return [];
    }
  }

  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  async generacionToken(
    apikey: string,
    secret: string,
    payload: object,
  ): Promise<string | null> {
    //TODO: Manejar de mejor manera los secrets
    const apiKeyData = this.validateApiKey(apikey);

    if (!apiKeyData) {
      this.logger.warn(`API key no encontrada: ${apikey}`);
      return null;
    }

    if (!apiKeyData.secretHash) {
      this.logger.error(
        `El hash del secreto es undefined para la API key: ${apikey}`,
      );
      return null;
    }

    this.logger.log(`Validating secret for API key: ${apikey}`);

    const isSecretValid = await this.validateSecret(
      secret,
      apiKeyData.secretHash,
    );
    this.logger.log(`Secret validation result: ${isSecretValid}`);

    if (isSecretValid) {
      //TODO : Manejar los tiempos de manera logica
      const token = jwt.sign(payload, secret, {
        algorithm: 'HS256',
        expiresIn: '30m',
      });
      this.logger.log(`Token generado para ${apikey}`, {
        apikey,
        timestamp: new Date().toISOString(),
      });
      return token;
    }

    this.logger.warn(`Intento fallido de generar token para ${apikey}`, {
      apikey,
      timestamp: new Date().toISOString(),
    });
    return null;
  }

  private validateApiKey(apikey: string): ApiKey | null {
    //TODO: considerar talvez una forma de manejar de mejor forma la APIKEY, talvez manejandolo por variable de entorno.
    const apiKeyData =
      this.apiKeys.find((key) => key.apikey === apikey) || null;
    if (apiKeyData) {
      this.logger.log(`API key validada: ${apikey}`, {
        apikey,
        timestamp: new Date().toISOString(),
      });
    } else {
      this.logger.warn(`API key inválida: ${apikey}`, {
        apikey,
        timestamp: new Date().toISOString(),
      });
    }
    return apiKeyData;
  }

  private async validateSecret(
    secret: string,
    secretHash: string,
  ): Promise<boolean> {
    try {
      //TODO: considerar talvez una forma de manejar de mejor forma el secret.
      return await bcrypt.compare(secret, secretHash);
    } catch (error) {
      this.logger.error(`Error al comparar el secreto: ${error.message}`);
      return false;
    }
  }
}
