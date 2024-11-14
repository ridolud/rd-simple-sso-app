import { IAccessPayload } from 'src/jwt/interfaces/access-token.interface';
import { IToken } from 'src/jwt/interfaces/token.interface';

export interface IEmailPayload extends IAccessPayload {}

export interface IEmailToken extends IEmailPayload, IToken {}
