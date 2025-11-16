/**
 * File contains the controller of authentication and authorization
 */

import { FastifyReply, FastifyRequest, FastifyInstance } from "fastify";
import { isInvalid } from "../utils/util";
import { OAuth2Client } from 'google-auth-library'
import bcrypt from 'bcryptjs';
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../utils/httpUtils";
import { createOneRecord, getSingleRecord, updateRecord } from "../utils/sql/sqlUtils";
import { User } from "../entities/User";
import { FindOneOptions } from "typeorm";
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const loginWithEmailAndPassword = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        
        const { email, password } = req.body as { email : string, password: string };

        if(isInvalid(email) || isInvalid(password)) {
            req.server.log.error('Invalid fields found in request body. Returning 404 response!');
            return reply.code(HTTP_STATUS_CODE.BAD_REQUEST).send({ status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: "Invalid Fields Found!" });
        }

        const query: FindOneOptions<User> = {
          where: { email }
        }
        const existingUser: Partial<User> = await getSingleRecord(User, query);

        if(isInvalid(existingUser)) {
            req.server.log.error("User with email does not exists. Returning not found!");
            return reply.code(HTTP_STATUS_CODE.NOT_FOUND).send({ status: HTTP_STATUS_MESSAGES.NOT_FOUND, message: 'User Not Found' });
        }

        const userPasswordMatch = await bcrypt.compare(password, existingUser.password);

        if(!userPasswordMatch) {
            req.server.log.error("Password does not match for the user with email. Returning forbidden response!");
            return reply.code(HTTP_STATUS_CODE.FORBIDDEN).send({ status: HTTP_STATUS_MESSAGES.FORBIDDEN, message: "Invalid Credentials!" });
        }

        const { accessToken, refreshToken } = generateTokens({userId: existingUser.id.toString(), role: existingUser.role }, req.server);

        reply
        .setCookie('token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 15 * 60, // 15 minutes
        })
        .setCookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        });

        return reply.code(200).send({ 
            status: HTTP_STATUS_MESSAGES.ACCEPTED,
            message: "User logged in successfully!",
            data: {
                firstName: existingUser.firstName,
                lastName: existingUser.lastName,
                refreshToken: refreshToken,
                token: accessToken,
                email: existingUser.email,
                avatar: existingUser.avatar,
                newComer: false
            }
        })
    
    } catch (error) {
        req.server.log.error(`Error in loginWithEmailAndPassword: ${error.message}`);
        return reply.code(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Something went wrong. Please contact Admin!" });
    }
}

export const signUpWithEmailAndPassword = async (req: FastifyRequest<{ Body: SignUpBody }>, reply: FastifyReply) => {
    try {
        
        req.server.log.info("Signing up user with email and password");

        const { email, password, userName, role, firstName, lastName } = req.body;
        
        const query: FindOneOptions<User> = {
          where: { email }
        }

        const existingUser: Partial<User> = await getSingleRecord(User, query);

        if(!isInvalid(existingUser)) {

            req.server.log.info("User already exists with email.");

            if(!isInvalid(existingUser.googleId)) {
                req.server.log.info("User has signed up with google previously.");
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: "Please try login with google!" });
            } else {
                return reply.code(HTTP_STATUS_CODE.BAD_REQUEST).send({ status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: "User with email already exists!" })
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await createOneRecord(User, { 
            firstName, lastName, email, userName, role, password: hashedPassword
        });

        req.server.log.info("User created. Generating access and refresh token.");

        const { accessToken, refreshToken } = generateTokens({ userId: newUser.id, role }, req.server);

        const updateQuery = { email }
        await updateRecord(User, updateQuery, { refreshToken });
        
        reply
        .setCookie('token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 15 * 60, // 15 minutes
        })
        .setCookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        });

        return reply.code(200).send({ 
            status: HTTP_STATUS_MESSAGES.ACCEPTED,
            message: "User Created!",
            data: {
                firstName: firstName,
                lastName: lastName,
                refreshToken: refreshToken,
                token: accessToken,
                email,
                newComer: false
            }
        });
        
    } catch (error) {
        
        req.server.log.error(`Error in ${signUpWithEmailAndPassword.name}: ${error.message}`);
        reply.code(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: `Error creating user. Please try after some time: ${error.message}` });
        
    }
}

export const generateTokens = (
  payload: TokenPayload,
  server: FastifyInstance
) => {
  const accessToken = server.jwt.sign(payload, { expiresIn: '15m' });
  const refreshToken = server.jwt.sign(payload, { expiresIn: '7d' });

  return { accessToken, refreshToken };
};

export const googleAuthLogin = async (req: FastifyRequest,reply: FastifyReply) => {
  try {

    const logger = req.server.log;
    logger.info('Logging in user using google.');

    const { token } = req.body as { token: string };

    logger.info('Authenticating the token with google.');

    let ticket: any;

    try {
      ticket = await googleClient.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
    } catch (error) {
      logger.error(
        'Error in validating google token. Invalid google token found for authentication.'
      );
      return reply.status(HTTP_STATUS_CODE.BAD_GATEWAY).send({
        status: HTTP_STATUS_MESSAGES.BAD_GATEWAY,
        message: 'Invalid google auth token found.',
      });
    }

    const { sub, email, picture, given_name, family_name } =
      ticket.getPayload();

    logger.debug('Found user data from google', {
      sub,
      email,
      picture,
      given_name,
      family_name,
    });

    logger.info('Checking for the existing user.');

    const query: FindOneOptions<User> = {
      where: { googleId: sub }
    }
    const existingUser: Partial<User> = await getSingleRecord(User, query);

    if (isInvalid(existingUser)) {
      logger.info('User not found. Creating new user.');

      const hashedPassword = await bcrypt.hash(
        process.env.USER_DEFAULT_PASSWORD!,
        10
      );

      let baseUsername = `${given_name}${family_name ? family_name.charAt(0) : ""}`.toLowerCase();
      baseUsername = baseUsername.replace(/[^a-z0-9]/g, ""); // Remove special characters

      let username = baseUsername;

      const userNameQuery: FindOneOptions<User> = {
        where: { userName: username }
      }
      while (await getSingleRecord(User, userNameQuery)) {
          username = `${baseUsername}${Math.floor(1000 + Math.random() * 9000)}`; // Add a random 4-digit number
      }

      const defaultUserName =  username;

      const newUser = await createOneRecord(User, {
        firstName: given_name,
        lastName: family_name || '',
        email: email,
        avatar: picture,
        role: 'student',
        userName: defaultUserName,
        password: hashedPassword,
        googleId: sub,
      });

      logger.info('User created. Generating the access and refresh token.');

      const { accessToken, refreshToken } = generateTokens(
        { userId: newUser.id, role: 'student' },
        req.server
      );

      const query = { email }
      await updateRecord(User, query, { refreshToken });

      reply.setCookie('jwtToken', accessToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.ENVIRONMENT === 'production',
        sameSite: 'lax',
        path: '/',
      });

      reply.setCookie('refreshToken', refreshToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.ENVIRONMENT === 'production',
        sameSite: 'lax',
        path: '/',
      });

      logger.info('Returning success response.');
      return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
        status: HTTP_STATUS_MESSAGES.SUCCESS,
        data: {
          firstName: given_name,
          lastName: family_name,
          avatar: picture,
          userName: username,
          newComer: true,
          token: accessToken,
          refreshToken: refreshToken,
        },
      });
    } else {
      logger.info(
        'User already exists. Generating accessToken and refreshToken for user to send.'
      );

      if (isInvalid(existingUser.googleId)) {
        logger.error(
          'User does not have google id. Account was created with email and password. Returning Bad Request as response.'
        );
        return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
          status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
          message: 'Please login using email and password!',
        });
      }

      const { accessToken, refreshToken } = generateTokens(
        { userId: existingUser.id.toString(), role: existingUser.role }, req.server
      );

      const query = { email }
      await updateRecord(User, query, { refreshToken })

      reply.setCookie('jwtToken', accessToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.ENVIRONMENT === 'production',
        sameSite: 'lax',
        path: '/',
      });

      reply.setCookie('refreshToken', refreshToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.ENVIRONMENT === 'production',
        sameSite: 'lax',
        path: '/',
      });

      logger.info('Returning success response.');
      return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
        status: HTTP_STATUS_MESSAGES.SUCCESS,
        data: {
          firstName: existingUser.firstName,
          lastName: existingUser.lastName,
          email: existingUser.email,
          avatar: existingUser.avatar,
          userName: existingUser.userName,
          newComer: false,
          token: accessToken,
          refreshToken: refreshToken,
        },
      });
    }
  } catch (error: any) {
    req.server.log.error(`Error in googleAuthLogin: ${error.message}`);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: 'Some error occurred while logging in with google',
      error: error.message,
    });
  }
};

export const logoutUser = async (req: FastifyRequest, reply: FastifyReply) => {
  try {

    reply.clearCookie('jwtToken');
    reply.clearCookie('refreshToken');
    return reply.code(HTTP_STATUS_CODE.SUCCESS).send({ status: HTTP_STATUS_MESSAGES.ACCEPTED, message: "Logged out successfully!" });

  } catch (error) {
    
    req.server.log.error(`Error in ${logoutUser.name} : ${error.message}`);
    return reply.code(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Error in logging out user. Please contact admin!" });

  }
}