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

/**
 * A rejection returned when Hawk validation fails
 * @param cause Cause why validation failed
 * @param challengeHeaders Challenge headers to be returned to the client
 */
case class HawkRejection(cause: HawkError, challengeHeaders: List[HttpHeader]) extends Rejection

abstract sealed class HawkError(val code: StatusCode, val message: String)

object HawkError {

  /**
   * Returned when an exception is encountered while retrieving a Hawk user
   * 
   * @param e Cause why user cannot be retrieved
   */
  case class UserRetrievalError(e: Throwable) extends HawkError(StatusCodes.InternalServerError, s"An error occurred while retrieving a hawk user: ${e.getMessage}")

  /**
   * Returned when Hawk credentials are not provided either in the `Authorization` header or in the bewit parameter
   */
  case object CredentialsMissingError extends HawkError(StatusCodes.Unauthorized, "Missing credentials")

  /**
   * Returned when a Hawk user with the given credentials is not present. Given the id attribute in the `Authorization` header or in
   * the bewit, if the supplied [[UserRetriever]] cannot retrieve a Hawk user with the given id, this error is returned
   */
  case object InvalidCredentialsError extends HawkError(StatusCodes.Unauthorized, "Invalid credentials")

  /**
   * Returned when the calculated MAC is different from the MAC supplied by the client
   */
  case object InvalidMacError extends HawkError(StatusCodes.Unauthorized, "Bad mac")

  /**
   * Returned when the calculated payload hash is different from the one supplied by the client
   */
  case object InvalidPayloadHashError extends HawkError(StatusCodes.Unauthorized, "Bad payload hash")

  /**
   * Returned when the nonce provided by the client has already been used in a previous request. When this error is returned,
   * it is most likely that the request has been replayed.
   */
  case object InvalidNonceError extends HawkError(StatusCodes.Unauthorized, "Invalid nonce")

  /**
   * Returned when the client provided Hawk authorization credentials both in the Http `Authorization` header and in the bewit parameter
   */
  case object MultipleAuthenticationError extends HawkError(StatusCodes.BadRequest, "Multiple authentications")

  /**
   * Returned when the bewit cannot be decoded
   */
  case object InvalidBewitEncodingError extends HawkError(StatusCodes.BadRequest, "Invalid bewit encoding")

  /**
   * Returned when the bewit has missing or extra components. A bewit parameter should have exactly four components (`id`, `exp`, `mac`, and `ext`)
   */
  case object InvalidBewitStructureError extends HawkError(StatusCodes.BadRequest, "Invalid bewit structure")

  /**
   * Returned when any of the bewit components (`id`, `exp`, `mac`, and `ext`) is missing
   */
  case object MissingBewitAttributesError extends HawkError(StatusCodes.BadRequest, "Missing bewit attributes")

  /**
   * Returned when the Http method of the request is not supported. Usually returned when a request with a bewit parameter is anything other than
   * a `GET` request
   */
  case object InvalidMethodError extends HawkError(StatusCodes.Unauthorized, "Invalid method")

  /**
   * Returned when the bewit has already expired
   */
  case object AccessExpiredError extends HawkError(StatusCodes.Unauthorized, "Access expired")

  /**
   * Returned when the timestamp provided in the `Authorization` header is already outside the maximum allowable timeframe
   * @param hawkUser Currrent hawk user associated with the request
   */
  case class StaleTimestampError(hawkUser: HawkUser) extends HawkError(StatusCodes.Unauthorized, "Stale timestamp")

}
