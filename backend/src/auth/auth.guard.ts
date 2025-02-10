import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Types } from 'mongoose';
import { Observable } from 'rxjs';
//import { JWT_KEY } from 'src/constant';
const JWT_KEY = '12345';
@Injectable()

export class AuthGuard implements CanActivate {



  constructor(private jwtSerive: JwtService) { }


  // canActivate(
  //   context: ExecutionContext,
  // ): boolean | Promise<boolean> | Observable<boolean> {
  async canActivate(context: ExecutionContext): Promise<boolean> {

    // getting heeader

    const request: Request = context.switchToHttp().getRequest();


    const authToken = request.headers['authorization'] || ''
    if (!authToken || !authToken.startsWith("Bearer ")) {
      throw new UnauthorizedException("Please Login First")
      return
    }
    const token = authToken.split(" ")[1]
    if (!token) {
      throw new UnauthorizedException("Token not valid")
      return

    }

    try {
      const payload = await this.jwtSerive.verifyAsync(token, {
        secret: JWT_KEY
      })

      if (!payload.userId || !Types.ObjectId.isValid(payload.userId)) {
        throw new UnauthorizedException('Invalid user ID in token');
      }


      request['anyuser'] = payload
    } catch (error) {
      throw new UnauthorizedException();
    }





    return true;
  }
}
