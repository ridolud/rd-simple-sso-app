import { IToken } from 'src/jwt/interfaces/token.interface';

export interface IAccessPayload {
  id: string;
}

export interface IAccessToken extends IAccessPayload, IToken {}
