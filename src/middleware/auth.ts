import { Elysia } from 'elysia'

export const authMiddleware = new Elysia()
  .derive(({ request }) => {
    const authHeader = request.headers.get('authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'No authorization header' }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json'
        }
      })
    }

    const token = authHeader.split(' ')[1]
    if (!token) {
      return new Response(JSON.stringify({ error: 'No token provided' }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json'
        }
      })
    }

    return {
      token
    }
  }) 