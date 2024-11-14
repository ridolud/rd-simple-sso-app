import { IToken } from 'src/jwt/interfaces/token.interface';
import { IAccessPayload } from './access-token.interface';

export interface IRefreshPayload extends IAccessPayload {
  tokenId: string;
}

export interface IRefreshToken extends IRefreshPayload, IToken {}
