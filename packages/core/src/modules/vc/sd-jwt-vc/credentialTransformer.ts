import { DecodedSDJwt, getClaimsSync } from '@sd-jwt/decode'
import { Hasher } from '../../../crypto'
import { CredoError } from '../../../error'
import { isJsonObject } from '../../../types'
import { W3cV2Credential, W3cV2CredentialOptions } from '../models/credential/W3cV2Credential'

export function sdJwtVcHasher(data: string | ArrayBufferLike, alg: string) {
  return Hasher.hash(typeof data === 'string' ? data : new Uint8Array(data), alg)
}

export function getCredentialFromSdJwtPayload(sdJwt: DecodedSDJwt): W3cV2Credential {
  const { header, payload } = sdJwt.jwt

  if ('typ' in header && header.typ !== 'vc+sd-jwt') {
    throw new CredoError(`The provided W3C VC SD-JWT does not have the correct 'typ' header.`)
  }

  if ('cyt' in header && header.cyt !== 'vc') {
    throw new CredoError(`The provided W3C VC SD-JWT does not have the correct 'cyt' header.`)
  }

  const claims = getClaimsSync(payload, sdJwt.disclosures, sdJwtVcHasher)
  if (!isJsonObject(claims)) {
    throw new CredoError('SD-JWT claims are not a valid JSON object')
  }

  // TODO: does this work and ensures validation?
  return new W3cV2Credential(claims as W3cV2CredentialOptions)
}
