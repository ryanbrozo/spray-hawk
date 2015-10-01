/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Ryan C. Brozo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.ryanbrozo.spray.hawk

import spray.http.{StatusCodes, StatusCode, HttpHeader}
import spray.routing.Rejection

case class HawkRejection(error: HawkError, challengeHeaders: List[HttpHeader]) extends Rejection

abstract sealed class HawkError(val code: StatusCode, val message: String)

object HawkError {

  case class UserRetrievalError(e: Throwable) extends HawkError(StatusCodes.InternalServerError, s"An error occurred while retrieving a hawk user: ${e.getMessage}")

  case object CredentialsMissingError extends HawkError(StatusCodes.Unauthorized, "Missing credentials")

  case object InvalidCredentialsError extends HawkError(StatusCodes.Unauthorized, "Invalid credentials")

  case object InvalidMacError extends HawkError(StatusCodes.Unauthorized, "Bad mac")

  case object InvalidPayloadHashError extends HawkError(StatusCodes.Unauthorized, "Bad payload hash")

  case object InvalidNonceError extends HawkError(StatusCodes.Unauthorized, "Invalid nonce")

  case object MultipleAuthenticationError extends HawkError(StatusCodes.BadRequest, "Multiple authentications")

  case object InvalidBewitEncodingError extends HawkError(StatusCodes.BadRequest, "Invalid bewit encoding")

  case object InvalidBewitStructureError extends HawkError(StatusCodes.BadRequest, "Invalid bewit structure")

  case object MissingBewitAttributesError extends HawkError(StatusCodes.BadRequest, "Missing bewit attributes")

  case object InvalidMethodError extends HawkError(StatusCodes.Unauthorized, "Invalid method")

  case object AccessExpiredError extends HawkError(StatusCodes.Unauthorized, "Access expired")

  case class StaleTimestampError(hawkUser: HawkUser) extends HawkError(StatusCodes.Unauthorized, "Stale timestamp")

}
