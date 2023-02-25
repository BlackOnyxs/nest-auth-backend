import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';

import * as bcrypt from 'bcrypt';

import { CreateUserDto, LoginUserDto } from './dto';
import { User } from './entities/auth.entity';
import { JwtPayload } from './interfaces';

@Injectable()
export class AuthService {

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto) {
    
    try {
      const { password, ...userData } = createUserDto;
      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync( password, 10 )
      });

      await this.userRepository.save( user );
      delete user.password;
      
      return {
        ...user,
        token: this.getJwt({ id: user.id })
      }
    } catch (error) {
      this.handleDBError(error)
    }
  }

  async login(loginUserDto: LoginUserDto){
    
    const { password, email } = loginUserDto;
    // console.log(password, email)

    const user = await this.userRepository.findOne({
      where: { email },
      select: { email: true, password: true, id: true }
    });
    console.log(user)

    if ( !user ) {
      throw new UnauthorizedException(`Credentials are not valid`);
    }

    if ( !bcrypt.compareSync( password, user.password ) ) {
      throw new UnauthorizedException(`Credentials are not valid`);
    }

    return {
      ...user,
      token: this.getJwt({ id: user.id })
    }
  }

  checkAuthStatus( user: User ) {
    delete user.roles;
    return {
      ...user,
      token: this.getJwt({ id: user.id })
    }
  }

  private getJwt( payload: JwtPayload ) {
    return this.jwtService.sign( payload );
  }

  private handleDBError(error:any): never {
    if ( error.code === '23505' ) {
      throw new BadRequestException(error.detail);
    }

    console.log(error);

    throw new InternalServerErrorException('Please check server logs')
  }

  

  
}
