import { Transform, TransformationType } from 'class-transformer'
import { ValidationError } from 'class-validator'
import { ClassValidationError, CredoError } from '../../../../error'
import { SingleOrArray } from '../../../../types'
import { JsonTransformer } from '../../../../utils'
import { W3cV2SdJwtVerifiableCredential } from '../../sd-jwt-vc/W3cV2SdJwtVerifiableCredential'
import type { ClaimFormat } from '../ClaimFormat'

const getCredential = (v: unknown) => {
  try {
    if (typeof v === 'string') {
      return W3cV2SdJwtVerifiableCredential.fromCompact(v)
    }
  } catch (error) {
    if (error instanceof ValidationError || error instanceof ClassValidationError) throw error
    throw new CredoError(`Value '${v}' is not a valid W3cV2VerifiableCredential. ${error.message}`)
  }

  throw new CredoError(`Value '${v}' is not a valid W3cV2VerifiableCredential.`)
}

const getEncoded = (v: unknown) => (v instanceof W3cV2SdJwtVerifiableCredential ? v.compact : JsonTransformer.toJSON(v))

export function W3cV2VerifiableCredentialTransformer() {
  return Transform(({ value, type }: { value: SingleOrArray<unknown>; type: TransformationType }) => {
    if (type === TransformationType.PLAIN_TO_CLASS) {
      return Array.isArray(value) ? value.map(getCredential) : getCredential(value)
    }
    if (type === TransformationType.CLASS_TO_PLAIN) {
      if (Array.isArray(value)) return value.map(getEncoded)
      return getEncoded(value)
    }
    // PLAIN_TO_PLAIN
    return value
  })
}

export type W3cV2VerifiableCredential<Format extends ClaimFormat.SdJwtVc | unknown = unknown> =
  Format extends ClaimFormat.SdJwtVc ? W3cV2SdJwtVerifiableCredential : W3cV2SdJwtVerifiableCredential
