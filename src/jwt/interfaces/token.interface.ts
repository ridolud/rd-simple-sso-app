export interface IToken {
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  sub: string;
}
