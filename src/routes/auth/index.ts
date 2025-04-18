import Elysia from "elysia";
import { error as elysiaError } from "elysia";
import { Auth } from "../../utils/auth";
import {
  loginModel,
  loginPasswordModel,
  registerModel,
  registerPasswordModel,
} from "./models";
import jwt from "@elysiajs/jwt";
import { User } from "../../utils/user";
import { hash } from "@node-rs/bcrypt"; // Using bcrypt instead of bun's password
import { rateLimit } from "@elysiajs/rate-limit"; // Using official Elysia rate limit plugin
import { keyGenerator } from "../../utils/generator";

// Define types for the context
type JwtContext = {
  jwt: ReturnType<typeof jwt>;
};

type RequestContext = {
  body: any;
};

export const authentication = new Elysia({ prefix: "/authentication" })
  .use(
    jwt({
      name: "jwt",
      secret: process.env.JWT_SECRET as string,
    }),
  )
  .use(
    rateLimit({
      scoping: "scoped",
      duration: 200 * 1000,
      generator: keyGenerator,
    }),
  )
  .post(
    "/login-otp",
    async ({ body, jwt }: RequestContext & JwtContext) => {
      const { email, otp } = body;

      const auth = new Auth();
      const result = await auth.Login(email, otp);

      switch(result.status){
        case 400:
          return elysiaError(result.status, result.message)
          break;
          
        case 200:
          const token = await jwt.sign({ id: result.result });
          return token
          break;
          
        default:
          return elysiaError(500, "Internal Server Error");
      }
    },
    {
      body: loginModel,
      detail: {
        tags: ["Authentication"],
      },
    },
  )

  .post(
    "/login",
    async ({ body, jwt }: RequestContext & JwtContext) => {
      const { email, password } = body;

      const auth = new Auth();
      const result = await auth.LoginWithPassword(email, password);
      
      switch(result.status){
        case 400:
          return elysiaError(result.status, result.message)
          break;
          
        case 200:
          const token = await jwt.sign({ id: result.result });
          return token
          break;
          
        default:
          return elysiaError(500, "Internal Server Error");
      }

    },
    {
      body: loginPasswordModel,
      detail: {
        tags: ["Authentication"],
      },
    },
  )

  .post(
    "/register",
    async ({ body }: RequestContext) => {
      const { firstName, lastName, phoneNumber, email, photoUrl, password } =
        body;

      const userObj = new User();

      const result = await userObj.createWithPassword(
        firstName,
        lastName,
        phoneNumber,
        email,
        photoUrl,
        password,
      );

      switch(result.status){
        case 400:
          return elysiaError(result.status, result.message)
          break;
          
        case 200:
          return result.result
          break;
          
        default:
          return elysiaError(500, "Internal Server Error");
      }
    },
    {
      body: registerPasswordModel,
      detail: {
        tags: ["Authentication"],
      },
    },
  )

  .post(
    "/register-otp",
    async ({ body }: RequestContext) => {
      const { firstName, lastName, phoneNumber, email, photoUrl } = body;

      const userObj = new User();

      const result = await userObj.create(
        firstName,
        lastName,
        phoneNumber,
        email,
        photoUrl,
      );

      switch(result.status){
        case 400:
          return elysiaError(result.status, result.message)
          break;
          
        case 200:
          return result.result
          break;
          
        default:
          return elysiaError(500, "Internal Server Error");
      }
    },
    {
      body: registerModel,
      detail: {
        tags: ["Authentication"],
      },
    },
  );
