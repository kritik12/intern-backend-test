import fastify from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    jwt: {
      sign: (payload: any, options?: any) => string;
      verify: (token: string, options?: any) => Promise<any>; 
    };
  }
  interface FastifyJWT {
    payload: {
      id: string; 
    };
  }

  interface FastifyRequest {
    jwtVerify: () => Promise<void>; 
    user: {
      id: string;
      username: string;
    };
  }
}
