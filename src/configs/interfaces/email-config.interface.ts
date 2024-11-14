interface IMailAuth {
  user: string;
  pass: string;
}

export interface IMailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: IMailAuth;
}
