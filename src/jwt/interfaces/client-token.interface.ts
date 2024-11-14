import { IAccessPayload } from 'src/jwt/interfaces/access-token.interface';
import { IToken } from 'src/jwt/interfaces/token.interface';

export interface IClientPayload extends IAccessPayload {
  redirectUrl?: string;
}

export interface IClientToken extends IClientPayload, IToken {}
