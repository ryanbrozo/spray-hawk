/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Ryan C. Brozo
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
 */

package com.ryanbrozo.spray.hawk

import com.typesafe.config.ConfigFactory
import com.typesafe.scalalogging.StrictLogging
import spray.http.HttpHeaders._
import spray.http._
import spray.routing.RequestContext
import spray.routing.authentication.HttpAuthenticator

import scala.concurrent._
import scala.concurrent.duration._
import scala.language.{postfixOps, implicitConversions}
import scala.util.Try
import scalaz.Scalaz._
import scalaz._

object HawkAuthenticator extends Util {

  abstract sealed class HawkError() {
    val message: String
  }

  case object InvalidUserError extends HawkError {val message = "Unknown credentials"}
  case object InvalidMacError extends HawkError {val message = "Bad mac"}
  case object InvalidPayloadHashError extends HawkError {val message = "Bad payload hash"}
  case object InvalidNonceError extends HawkError {val message = "Invalid nonce"}
  case class StaleTimestampError(hawkUser: HawkUser) extends HawkError {val message = "Stale timestamp"}

  private val _conf = ConfigFactory.load()
  
  private[hawk] val _payloadValidationEnabled = _conf.getBoolean("spray.hawk.payloadValidation")
  private[hawk] val _timeSkewValidationEnabled = _conf.getBoolean("spray.hawk.timeSkewValidation")
  private[hawk] val _timeSkewInSeconds = _conf.getLong("spray.hawk.timeSkewInSeconds")
  
  def apply[U <: HawkUser](realm: String, userRetriever: UserRetriever[U])(implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(Util.defaultTimestampProvider, defaultNonceValidator)(realm, userRetriever)

  def apply[U <: HawkUser](tsProvider: TimeStampProvider)(realm: String,userRetriever: UserRetriever[U])
                          (implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(tsProvider, defaultNonceValidator)(realm, userRetriever)

  def apply[U <: HawkUser](nonceValidator: NonceValidator)(realm: String,userRetriever: UserRetriever[U])
                          (implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(Util.defaultTimestampProvider, nonceValidator)(realm, userRetriever)

  def apply[U <: HawkUser](tsProvider: TimeStampProvider, nonceValidator: NonceValidator)(realm: String,userRetriever: UserRetriever[U])
                          (implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(tsProvider, nonceValidator)(realm, userRetriever)

}

/**
 * A HawkAuthenticator is a ContextAuthenticator that uses credentials passed to the server via the
 * HTTP `Authorization` header to authenticate the user and extract a user object.
 *
 */
class HawkAuthenticator[U <: HawkUser](timestampProvider: TimeStampProvider, nonceValidator: NonceValidator)(realm: String,
                                userRetriever: UserRetriever[U])
                               (implicit val executionContext: ExecutionContext)
  extends HttpAuthenticator[U]
  with Util
  with StrictLogging {
  
  import HawkAuthenticator._

  val SCHEME = "Hawk"

  private def validateCredentials(hawkUserOption: Option[U], hawkCredentials: HawkHttpCredentials): \/[HawkError, Option[U]] = {

    def checkMac(implicit hawkUser: U): \/[HawkError, Option[U]] = {
      (for {
        mac <- hawkCredentials.mac if mac == Hawk(hawkUser, hawkCredentials.options).mac
      } yield Option(hawkUser).right[HawkError]) | InvalidMacError.left[Option[U]]
    }

    def checkPayload(implicit hawkUser: U): \/[HawkError, Option[U]] = {
      hawkCredentials.hash match {
        case Some(hash) if _payloadValidationEnabled =>
          // According to Hawk specs, payload validation should should only
          // happen if MAC is validated.
          (for {
            (payload, contentType) ← extractPayload(hawkCredentials.request)
            hawkPayload ← Option(HawkPayload(payload, contentType, hawkUser.algorithm.hashAlgo))
            if hawkPayload.hash == hash
          } yield Option(hawkUser).right[HawkError]) | InvalidPayloadHashError.left[Option[U]]
        case _ =>
          // 'hash' is not supplied? then no payload validation is needed.
          // Return the obtained credentials
          Some(hawkUser).right[HawkError]
      }
    }

    def checkNonce(implicit hawkUser: U): \/[HawkError, Option[U]] = {
      hawkCredentials.nonce match {
        case Some(n) if nonceValidator(n, hawkUser.key, hawkCredentials.ts) => Option(hawkUser).right[HawkError]
        case _ => InvalidNonceError.left[Option[U]]
      }
    }

    def checkTimestamp(implicit hawkUser: U): \/[HawkError, Option[U]] = {
      if (_timeSkewValidationEnabled) {
        val timestamp = hawkCredentials.ts
        val currentTimestamp = timestampProvider()
        val lowerBound = currentTimestamp - _timeSkewInSeconds
        val upperBound = currentTimestamp + _timeSkewInSeconds
        if (lowerBound <= timestamp && timestamp <= upperBound)
          Option(hawkUser).right[HawkError]
        else
          StaleTimestampError(hawkUser).left[Option[U]]
      }
      else Option(hawkUser).right[HawkError]
    }

    hawkUserOption map { implicit hawkUser =>
      for {
        macOk <- checkMac
        payloadOk <- checkPayload
        nonceOk <- checkNonce
        tsOk <- checkTimestamp
      } yield tsOk
    } getOrElse InvalidUserError.left[Option[U]]
  }  

  override def getChallengeHeaders(httpRequest: HttpRequest): List[HttpHeader] = {
    // Unfortunately, due to the design of spray.io, there is a need to
    // do all the validation again just to create the required WWW-Authenticate headers.
    // This can be costly, since we need to call the supplied userRetriever function again.
    // See https://github.com/spray/spray/issues/938 for more details

    val hawkHttpCredentials = HawkHttpCredentials(httpRequest)
    val userTry = Try {
      // Assume the supplied userRetriever function can throw an exception
      userRetriever(hawkHttpCredentials.id)
    }
    userTry match {
      case scala.util.Success(userFuture) =>
        val f = userFuture map { validateCredentials(_, hawkHttpCredentials) } map {
          case -\/(err:StaleTimestampError) =>
            val currentTimestamp = timestampProvider()
            val params = Map(
              "ts" -> currentTimestamp.toString,
              "tsm" -> HawkTimestamp(currentTimestamp, err.hawkUser).mac,
              "error" -> err.message
            )
            `WWW-Authenticate`(HttpChallenge(SCHEME, realm, params)) :: Nil
          case _ =>
            `WWW-Authenticate`(HttpChallenge(SCHEME, realm)) :: Nil
        }
        Await.result(f, 60 milliseconds)
      case scala.util.Failure(e) =>
        logger.warn(s"An error occurred while retrieving a hawk user: ${e.getMessage}")
        `WWW-Authenticate`(HttpChallenge(SCHEME, realm)) :: Nil
    }
  }

  override def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext): Future[Option[U]] = {
    val hawkHttpCredentials = HawkHttpCredentials(ctx.request)
    val userTry = Try {
      // Assume the supplied userRetriever function can throw an exception
      userRetriever(hawkHttpCredentials.id)
    }
    userTry match {
      case scala.util.Success(userFuture) =>
        userFuture map { validateCredentials(_, hawkHttpCredentials) } map {
          case \/-(user) => user
          case _ => None
        }
      case scala.util.Failure(e) =>
        logger.warn(s"An error occurred while retrieving a hawk user: ${e.getMessage}")
        Future.successful(None)
    }
  }
}
