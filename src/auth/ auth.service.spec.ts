import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import * as fs from 'fs';
import * as path from 'path';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';

jest.mock('fs');

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('debería devolver null si la API key no se encuentra', async () => {
    const apikey = 'clave-invalida';
    const secret = 'secreto-correcto';
    const payload = { userId: 123, role: 'admin' };

    // Mock de fs.readFileSync para devolver una API key válida diferente
    jest.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify([
        {
          id: 1,
          name: 'Front Login Key',
          tipoToken: {
            id: 1,
            name: 'Login',
          },
          apikey: 'front-login-key',
          secretHash:
            '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjUM0VvZJ9AvjZ4zV9BwoY.eMoU.BK.',
        },
      ]),
    );

    const token = await service.generacionToken(apikey, secret, payload);

    expect(token).toBeNull();
  });

  it('debería devolver null si el secreto es incorrecto', async () => {
    const apikey = 'front-login-key';
    const secret = 'secreto-incorrecto';
    const payload = { userId: 123, role: 'admin' };

    // Mock de bcrypt.compare para devolver false
    jest.spyOn(bcrypt, 'compare').mockImplementation(async () => false);

    // Mock de fs.readFileSync para devolver la API key y el hash correctos
    jest.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify([
        {
          id: 1,
          name: 'Front Login Key',
          tipoToken: {
            id: 1,
            name: 'Login',
          },
          apikey: 'front-login-key',
          secretHash:
            '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjUM0VvZJ9AvjZ4zV9BwoY.eMoU.BK.',
        },
      ]),
    );

    const token = await service.generacionToken(apikey, secret, payload);

    expect(token).toBeNull();
  });

  it('debería generar un token válido si la API key y el secreto son correctos', async () => {
    const apikey = 'front-login-key';
    const secret = 'front-login-secret';
    const payload = { userId: 123, role: 'admin' };

    // Mock de bcrypt.compare para devolver true
    jest.spyOn(bcrypt, 'compare').mockImplementation(async () => true);

    // Mock de fs.readFileSync para devolver la API key y el hash correctos
    jest.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify([
        {
          id: 1,
          name: 'Front Login Key',
          tipoToken: {
            id: 1,
            name: 'Login',
          },
          apikey: 'front-login-key',
          secretHash:
            '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjUM0VvZJ9AvjZ4zV9BwoY.eMoU.BK.',
        },
      ]),
    );

    const token = await service.generacionToken(apikey, secret, payload);

    expect(token).not.toBeNull();

    const decoded = jwt.verify(token, secret);
    expect(decoded).toMatchObject(payload);
  });

  it('debería registrar un mensaje de advertencia si la API key no se encuentra', async () => {
    const apikey = 'clave-invalida';
    const secret = 'secreto-correcto';
    const payload = { userId: 123, role: 'admin' };

    const loggerSpy = jest.spyOn(service['logger'], 'warn');

    jest.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify([
        {
          id: 1,
          name: 'Front Login Key',
          tipoToken: {
            id: 1,
            name: 'Login',
          },
          apikey: 'front-login-key',
          secretHash:
            '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjUM0VvZJ9AvjZ4zV9BwoY.eMoU.BK.',
        },
      ]),
    );

    await service.generacionToken(apikey, secret, payload);

    expect(loggerSpy).toHaveBeenCalledWith(`API key no encontrada: ${apikey}`);
  });

  it('debería registrar un mensaje de advertencia si el secreto es incorrecto', async () => {
    const apikey = 'front-login-key';
    const secret = 'secreto-incorrecto';
    const payload = { userId: 123, role: 'admin' };

    const loggerSpy = jest.spyOn(service['logger'], 'warn');

    jest.spyOn(bcrypt, 'compare').mockImplementation(async () => false);

    jest.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify([
        {
          id: 1,
          name: 'Front Login Key',
          tipoToken: {
            id: 1,
            name: 'Login',
          },
          apikey: 'front-login-key',
          secretHash:
            '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjUM0VvZJ9AvjZ4zV9BwoY.eMoU.BK.',
        },
      ]),
    );

    await service.generacionToken(apikey, secret, payload);

    expect(loggerSpy).toHaveBeenCalledWith(
      `Intento fallido de generar token para ${apikey}`,
      {
        apikey,
        timestamp: expect.any(String),
      },
    );
  });

  it('debería generar un token válido y registrarlo si la API key y el secreto son correctos', async () => {
    const apikey = 'front-login-key';
    const secret = 'front-login-secret';
    const payload = { userId: 123, role: 'admin' };

    const loggerSpy = jest.spyOn(service['logger'], 'log');

    jest.spyOn(bcrypt, 'compare').mockImplementation(async () => true);

    jest.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify([
        {
          id: 1,
          name: 'Front Login Key',
          tipoToken: {
            id: 1,
            name: 'Login',
          },
          apikey: 'front-login-key',
          secretHash:
            '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjUM0VvZJ9AvjZ4zV9BwoY.eMoU.BK.',
        },
      ]),
    );

    const token = await service.generacionToken(apikey, secret, payload);

    expect(token).not.toBeNull();

    expect(loggerSpy).toHaveBeenCalledWith(`Token generado para ${apikey}`, {
      apikey,
      timestamp: expect.any(String),
    });
  });
});
