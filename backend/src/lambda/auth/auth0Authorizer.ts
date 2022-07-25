import { APIGatewayAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import Axios from 'axios'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
const jwksUrl = 'https://benedicta.us.auth0.com/.well-known/jwks.json'
let cachedCert: string

export const handler = async (event: APIGatewayAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.type)

  try {
    const jwtToken = await verifyToken(event)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(event: APIGatewayAuthorizerEvent): Promise<JwtPayload> {
  const token = getToken(event)
  const cert = await getCert()

  logger.info(`Verifying token ${token}`)

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(event: APIGatewayAuthorizerEvent): string {
  if (!event.type || event.type !== 'TOKEN')
    throw new Error('Expected "event.type" parameter to have value "TOKEN"');

  const authHeader = event.authorizationToken;
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}

async function getCert(): Promise<string> {
  if (cachedCert) return cachedCert

  logger.info(`Fetching certificate from ${jwksUrl}`)

  const res = await Axios.get(jwksUrl)
  const keys = res.data.keys

  if (!keys || !keys.length)
    throw new Error('No JWKS keys found!')

  const signingKeys = keys.filter(
    key => key.use === 'sig'
      && key.kty === 'RSA'
      && key.alg === 'RS256'
      && key.n
      && key.e
      && key.kid
      && (key.x5c && key.x5c.length)
  )

  if (!signingKeys.length)
    throw new Error('No JWKS signing keys found!')

  const key = signingKeys[0]
  const publicKey = key.x5c[0]

  cachedCert = createCert(publicKey)

  logger.info('Valid certificate found', cachedCert)

  return cachedCert
}

function createCert(cert: string): string {
  cert = cert.match(/.{1,64}/g).join('\n')
  return cert
}