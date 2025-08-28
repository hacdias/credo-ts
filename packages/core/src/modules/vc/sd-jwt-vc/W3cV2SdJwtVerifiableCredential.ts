import { DecodedSDJwt, decodeSdJwtSync } from '@sd-jwt/decode'
import { CredoError } from 'packages/core/src/error'
import { ClaimFormat } from '../models/ClaimFormat'
import { W3cV2Credential } from '../models/credential/W3cV2Credential'
import { getCredentialFromSdJwtPayload, sdJwtVcHasher } from './credentialTransformer'

export interface W3cV2SdJwtVerifiableCredentialOptions {
  compact: string
  sdJwt: DecodedSDJwt
}

export class W3cV2SdJwtVerifiableCredential {
  public readonly sdJwt: DecodedSDJwt
  public readonly compact: string
  public readonly credential: W3cV2Credential

  public constructor(options: W3cV2SdJwtVerifiableCredentialOptions) {
    this.sdJwt = options.sdJwt
    this.compact = options.compact
    this.credential = getCredentialFromSdJwtPayload(options.sdJwt)
  }

  public static fromCompact(compact: string) {
    const sdJwt = decodeSdJwtSync(compact, sdJwtVcHasher)

    return new W3cV2SdJwtVerifiableCredential({
      sdJwt,
      compact,
    })
  }

  public static fromDataUri(uri: string) {
    if (!uri.startsWith('data:application/vc+sd-jwt,')) {
      throw new CredoError(`The provided string is not a valid vc+sd-jwt data URI: "${uri}".`)
    }

    const compact = uri.slice('data:application/vc+sd-jwt,'.length)
    return W3cV2SdJwtVerifiableCredential.fromCompact(compact)
  }

  /**
   * The {@link ClaimFormat} of the credential. For SD-JWT credentials this is always `vc+sd-jwt`.
   */
  public get claimFormat(): ClaimFormat.SdJwtVc {
    return ClaimFormat.SdJwtVc
  }

  public get dataUri(): string {
    return `data:application/vc+sd-jwt,${this.compact}`
  }
}
