from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
class InsecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self,request:Request,call_next):
        response:Response=await call_next(request)
        response.headers.setdefault('X-Content-Type-Options','nosniff')
        response.headers.setdefault('Referrer-Policy','no-referrer')
        return response
