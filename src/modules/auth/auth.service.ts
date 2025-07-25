import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { User } from 'src/models/user.model';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { sendVerificationEmail, sendPasswordResetEmail } from 'src/utils/email.service';
import { CompleteProfileDto } from './dto/complete-profile.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User) private userModel: typeof User,
    private jwtService: JwtService,
  ) {}

  async register(email: string, password: string) {
    const existing = await this.userModel.findOne({ where: { email } });
    if (existing) throw new BadRequestException('User already exists');

    const hash = await bcrypt.hash(password, 10);
    await this.userModel.create({
      email,
      password: hash, 
      isVerified: false,
    });

    console.log(process.env.JWT_SECRET)

    const token = this.jwtService.sign(
      { email },
      { expiresIn: '24h' },
    );
    
    const verifyUrl = `http://localhost:4000/verify-email?email=${email}&token=${token}`;
    
    await sendVerificationEmail(email, verifyUrl);
    return { email, message: 'Verification link sent to email' };
  }

  async verifyEmailToken(token: string) {
  try {
    const payload = await this.jwtService.verifyAsync(token);
    const email = payload.email;

    const user = await this.userModel.findOne({ where: { email } });
    if (!user) throw new BadRequestException('User not found');
    if (user.isVerified) return { message: 'Already verified' };

    // console.log('BEFORE:', user.toJSON());
    // console.log(Object.keys(user.toJSON())); // should include 'isVerified'


    await user.update({ isVerified: true });

    const reloaded = await this.userModel.findOne({ where: { email } });
    // console.log('AFTER:', reloaded?.toJSON());

    return { message: 'Email verified. You can now log in.' };
  } catch (err) {
    console.error(err);
    throw new BadRequestException('Invalid or expired verification link');
  }
  }

  async login(email: string, password: string) {
    const user = await this.userModel.findOne({ where: { email }, raw: false });
    // console.log('Logging in:', user?.isVerified); // should now be true
    if (!user || !user.isVerified)
      throw new UnauthorizedException('Invalid credentials');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      throw new UnauthorizedException('Invalid credentials');

    const token = this.jwtService.sign({ sub: user.id, email: user.email });
    const userJson = user.toJSON();
    return { 
        user: {
            email: user.email, 
            firstName: user.firstName, 
            lastName: user.lastName, 
        }, 
        access_token: token 
    };
  }

  
  async completeProfile(userId: number, dto: CompleteProfileDto) {
      const user = await this.userModel.findByPk(userId);
      if (!user) throw new BadRequestException('User not found');
  
      await user.update({
          firstName: dto.firstName,
          lastName: dto.lastName,
        });
    const userJson = user.toJSON();
        
    return { 
        user: {
            email: user.email, 
            firstName: user.firstName, 
            lastName: user.lastName, 
        }, 
        message: 'Profile completed successfully.' 
    };
  }
  
  async getUserProfile(userId: number) {
      const user = await this.userModel.findByPk(userId);
      if (!user) throw new BadRequestException('User not found');
      return {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isVerified: user.isVerified,
          createdAt: user.createdAt,
        };
    }
    
    async resendVerification(email: string) {
        const user = await this.userModel.findOne({ where: { email } });
        if (!user) throw new BadRequestException('User not found');
        if (user.isVerified) return { message: 'User already verified' };
      
        const token = this.jwtService.sign({ email }, { expiresIn: '24h' });
        const verifyUrl = `http://localhost:3000/auth/verify-email?token=${token}`;
      
        await sendVerificationEmail(email, verifyUrl);
        return { email, message: 'Verification email resent' };
    }
    
    async sendResetPasswordLink(email: string) {
        const user = await this.userModel.findOne({ where: { email } });
        if (!user) throw new BadRequestException('User not found');
      
        const token = this.jwtService.sign({ email }, { expiresIn: '15m' });
        const resetUrl = `http://localhost:3000/auth/reset-password?token=${token}`;
      
        await sendPasswordResetEmail(email, resetUrl); 
        return { message: 'Reset password link sent' };
    }
    
    async resetPassword(token: string, newPassword: string) {
        try {
            const payload = await this.jwtService.verifyAsync(token);
            const user = await this.userModel.findOne({ where: { email: payload.email } });
            if (!user) throw new BadRequestException('Invalid user');
        
            const hash = await bcrypt.hash(newPassword, 10);
            await user.update({ password: hash });
        
            return { message: 'Password reset successful' };
        } catch (e) {
            throw new BadRequestException('Invalid or expired reset link');
        }
    }

}
