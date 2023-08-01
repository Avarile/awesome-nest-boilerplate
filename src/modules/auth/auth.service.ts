import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { validateHash } from '../../common/utils';
import type { RoleType } from '../../constants';
import { TokenType } from '../../constants';
import { UserNotFoundException } from '../../exceptions';
import { ApiConfigService } from '../../shared/services/api-config.service';
import type { UserEntity } from '../user/user.entity';
import { UserService } from '../user/user.service';
import { TokenPayloadDto } from './dto/TokenPayloadDto';
import type { UserLoginDto } from './dto/UserLoginDto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ApiConfigService,
    private userService: UserService,
  ) {}

  async createAccessToken(data: {
    role: RoleType;
    userId: Uuid;
  }): Promise<TokenPayloadDto> {
    return new TokenPayloadDto({
      expiresIn: this.configService.authConfig.jwtExpirationTime,
      accessToken: await this.jwtService.signAsync({
        userId: data.userId,
        type: TokenType.ACCESS_TOKEN,
        role: data.role,
      }),
    });
  }

  /***
   * login with email and password
   */
  async validateUser(userLoginDto: UserLoginDto): Promise<UserEntity> {
    const user = await this.userService.findOne({
      email: userLoginDto.email,
    });

    const isPasswordValid = await validateHash(
      userLoginDto.password,
      user?.password,
    );

    if (!isPasswordValid) {
      throw new UserNotFoundException();
    }

    return user!;
  }

  /***
   * login with google
   */
  // validateGoogleUser(response: unknown) {
  //   // eslint-disable-next-line @typescript-eslint/no-explicit-any
  //   if (!response.user) {
  //     throw new UserNotFoundException();
  //   } else {
  //     // eslint-disable-next-line @typescript-eslint/no-explicit-any
  //     return response.user;
  //   }
  // }
}
