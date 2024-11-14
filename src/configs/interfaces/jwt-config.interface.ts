export interface ISingleJwtConfig {
  secret: string;
  time: number;
}

export interface IJwtConfig {
  access: ISingleJwtConfig;
  client: ISingleJwtConfig;
  confirmation: ISingleJwtConfig;
  resetPassword: ISingleJwtConfig;
  refresh: ISingleJwtConfig;
}
