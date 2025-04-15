import { Elysia } from "elysia";
import { authentication } from "./routes/auth";
import swagger from "@elysiajs/swagger";
import cors from "@elysiajs/cors";
import { Otp } from "./routes/otp";
import { group } from "./routes/group";
import { rule } from "./routes/rules";
import { member } from "./routes/member";
import { jwt } from '@elysiajs/jwt'

// Define types for the context
type JwtContext = {
  jwt: {
    verify: (token: string) => Promise<any>;
  };
};

type RequestContext = {
  request: Request;
};

const app = new Elysia()
  .use(authentication)
  .use(Otp)
  .use(group)
  .use(rule)
  .use(member)
  .use(swagger())
  .use(cors({
    origin: ['http://localhost:3000', 'http://localhost:8080'], // Add your frontend URLs
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }))
  .use(jwt({
    name: 'jwt',
    secret: process.env.JWT_SECRET || 'your-secret-key'
  }))
  .derive(({ request, jwt }: RequestContext & JwtContext) => {
    const authHeader = request.headers.get('authorization')
    if (authHeader) {
      const token = authHeader.split(' ')[1]
      if (token) {
        try {
          const payload = jwt.verify(token)
          return { user: payload }
        } catch (error) {
          return { error: 'Invalid token' }
        }
      }
    }
    return {}
  })
  .get("/", () => "Hello Elysia")
  .listen(3000);

console.log(
  `🦊 Elysia is running at http://${app.server?.hostname}:${app.server?.port}`,
);
