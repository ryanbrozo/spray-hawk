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

import com.ryanbrozo.spray.hawk.HawkError._
import com.typesafe.config.ConfigFactory
import com.typesafe.scalalogging.StrictLogging
import spray.http.HttpHeaders._
import spray.http._
import spray.routing.RequestContext
import spray.routing.authentication.ContextAuthenticator

import scala.concurrent._
import scala.concurrent.duration._
import scala.language.{implicitConversions, postfixOps}
import scala.util.Try
import scalaz.Scalaz._
import scalaz._

object HawkAuthenticator {

  private val _conf = ConfigFactory.load()
  
  private[hawk] val _payloadValidationEnabled = _conf.getBoolean("spray.hawk.payloadValidation")
  private[hawk] val _timeSkewValidationEnabled = _conf.getBoolean("spray.hawk.timeSkewValidation")
  private[hawk] val _timeSkewInSeconds = _conf.getLong("spray.hawk.timeSkewInSeconds")
  private[hawk] val _maxUserRetrieverTimeInSeconds = _conf.getLong("spray.hawk.maxUserRetrieverTimeInSeconds") seconds
  
  def apply[U <: HawkUser](realm: String, userRetriever: UserRetriever[U])(implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(Util.defaultTimestampProvider, Util.defaultNonceValidator)(realm, userRetriever)

  def apply[U <: HawkUser](tsProvider: TimeStampProvider)(realm: String,userRetriever: UserRetriever[U])
                          (implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(tsProvider, Util.defaultNonceValidator)(realm, userRetriever)

  def apply[U <: HawkUser](nonceValidator: NonceValidator)(realm: String,userRetriever: UserRetriever[U])
                          (implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(Util.defaultTimestampProvider, nonceValidator)(realm, userRetriever)

  def apply[U <: HawkUser](tsProvider: TimeStampProvider, nonceValidator: NonceValidator)(realm: String,userRetriever: UserRetriever[U])
                          (implicit executionContext: ExecutionContext) =
    new HawkAuthenticator(tsProvider, nonceValidator)(realm, userRetriever)

}

/**
 * A `ContextAuthenticator` passed to Spray that validates the credentials passed via the HTTP `Authorization` header
 * using the Hawk Authentication protocol to authenticate the user and extract a user object.
 *
 * Example usage:
 *
 * {{{
 * // Our User model. This needs to extend the HawkUser trait for our UserCredentialsRetriever
 * // to work
 * case class User(name: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser
 *
 * // Our user credentials retriever. Currently it returns 'Bob' along with his hawk credentials
 * val userCredentialsRetriever: UserRetriever[User] = { id =>
 *     Future.successful {
 *       if (id == "dh37fgj492je") Some(User("Bob", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256))
 *       else None
 *     }
 * }
 *
 * val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)
 *
 * startServer(interface = "localhost", port = 8080) {
 *   path("secured") {
 *     authenticate(hawkAuthenticator) { user =>
 *       get {
 *         complete {
 *           s"Welcome to spray, \${user.name}!"
 *         }
 *       } ~
 *       post {
 *         entity(as[String]) { body =>
 *           complete {
 *             s"Welcome to spray, \${user.name}! Your post body was: \$body"
 *           }
 *         }
 *       }
 *     }
 *   }
 * }
 * }}}
 *
 */
class HawkAuthenticator[U <: HawkUser](timestampProvider: TimeStampProvider, nonceValidator: NonceValidator)(realm: String,
                                userRetriever: UserRetriever[U])
                               (implicit val executionContext: ExecutionContext)
  extends ContextAuthenticator[U]
  with StrictLogging {
  
  import HawkAuthenticator._

  val SCHEME = HEADER_NAME

  def apply(ctx: RequestContext) = {
    val hawkRequest = HawkRequest(ctx.request)
    authenticate(hawkRequest) map {
      case Right(u) ⇒ Right(u)
      case Left(e) ⇒ Left(HawkRejection(e, getChallengeHeaders(e)))
    }
  }

  /**
   * Checks if given bewit credentials are valid
   *
   * @param hawkUserOption Hawk user, wrapped in an Option
   * @param hawkRequest HawkRequest instance
   * @return Either a HawkError or the validated HawkUser
   */
  private def validateBewitCredentials(hawkUserOption: Option[U], hawkRequest: HawkRequest): \/[HawkError, U] = {
    def checkMethod(implicit hawkUser: U): \/[HawkError, U] = {
      if (hawkRequest.request.method != HttpMethods.GET)
        InvalidMacError.left[U]
      else
        hawkUser.right[HawkError]
    }

    def checkExpiry(implicit hawkUser: U): \/[HawkError, U] = {
      val currentTimestamp = timestampProvider()
      if (hawkRequest.bewitAttributes.exp * 1000 <= currentTimestamp)
        AccessExpiredError.left[U]
      else
        hawkUser.right[HawkError]
    }

    def checkMac(implicit hawkUser: U): \/[HawkError, U] = {
      if (hawkRequest.bewitAttributes.mac != Hawk(hawkUser, hawkRequest.bewitOptions, Hawk.TYPE_BEWIT).mac)
        InvalidMacError.left[U]
      else
        hawkUser.right[HawkError]
    }

    hawkUserOption map { implicit hawkUser =>
      for {
        methodOk <- checkMethod
        expiryOk <- checkExpiry
        macOk <- checkMac
      } yield expiryOk
    } getOrElse InvalidCredentialsError.left[U]
  }

  /**
   * Checks if given Authorization header is valid
   *
   * @param hawkUserOption Hawk user, wrapped in an Option
   * @param hawkRequest HawkRequest instance
   * @return Either a HawkError or the validated HawkUser
   */
  private def validateAuthHeaderCredentials(hawkUserOption: Option[U], hawkRequest: HawkRequest): \/[HawkError, U] = {

    def checkMac(implicit hawkUser: U): \/[HawkError, U] = {
      (for {
        mac <- hawkRequest.authHeaderAttributes.mac if mac == Hawk(hawkUser, hawkRequest.hawkOptions, Hawk.TYPE_HEADER).mac
      } yield hawkUser.right[HawkError]) | InvalidMacError.left[U]
    }

    def checkPayload(implicit hawkUser: U): \/[HawkError, U] = {
      hawkRequest.authHeaderAttributes.hash match {
        case Some(hash) if _payloadValidationEnabled =>
          // According to Hawk specs, payload validation should should only
          // happen if MAC is validated.
          (for {
            (payload, contentType) ← hawkRequest.payload
            hawkPayload ← Option(HawkPayload(payload, contentType, hawkUser.algorithm.hashAlgo))
            if hawkPayload.hash == hash
          } yield hawkUser.right[HawkError]) | InvalidPayloadHashError.left[U]
        case _ =>
          // 'hash' is not supplied? then no payload validation is needed.
          // Return the obtained credentials
          hawkUser.right[HawkError]
      }
    }

    def checkNonce(implicit hawkUser: U): \/[HawkError, U] = {
      hawkRequest.authHeaderAttributes.nonce match {
        case Some(n) if nonceValidator(n, hawkUser.key, hawkRequest.authHeaderAttributes.ts) => hawkUser.right[HawkError]
        case _ => InvalidNonceError.left[U]
      }
    }

    def checkTimestamp(implicit hawkUser: U): \/[HawkError, U] = {
      if (_timeSkewValidationEnabled) {
        val timestamp = hawkRequest.authHeaderAttributes.ts
        val currentTimestamp = timestampProvider()
        val lowerBound = currentTimestamp - _timeSkewInSeconds
        val upperBound = currentTimestamp + _timeSkewInSeconds
        if (lowerBound <= timestamp && timestamp <= upperBound)
          hawkUser.right[HawkError]
        else
          StaleTimestampError(hawkUser).left[U]
      }
      else hawkUser.right[HawkError]
    }

    hawkUserOption map { implicit hawkUser =>
      for {
        macOk <- checkMac
        payloadOk <- checkPayload
        nonceOk <- checkNonce
        tsOk <- checkTimestamp
      } yield tsOk
    } getOrElse InvalidCredentialsError.left[U]
  }

  /**
   * Produces a list of Http Challenge Headers
   *
   * @param hawkError HawkError used to produce the challenge headers
   * @return List of challenge headers
   */
  private def getChallengeHeaders(hawkError: HawkError): List[HttpHeader] = {
    val params = hawkError match {
      case err: StaleTimestampError =>
        val currentTimestamp = timestampProvider()
        Map(
          "ts" -> currentTimestamp.toString,
          "tsm" -> HawkTimestamp(currentTimestamp, err.hawkUser).mac,
          "error" -> err.message
        )
      case err =>
        Map(
          "error" -> err.message
        )
    }
    `WWW-Authenticate`(HttpChallenge(SCHEME, realm, params)) :: Nil
  }

  /**
   * Authenticates an incoming request. This method checks if Hawk credentials came from bewit or Authorization header
   * and validates accordingly
   *
   * @param hawkRequest HawkRequest instance to validate.
   * @return Either a HawkError, if authorization is not valid, or a HawkUser if authorization is valid. Result is wrapped
   *         in a Future
   */
  private def authenticate(hawkRequest: HawkRequest): Future[Either[HawkError, U]] = {
    def validate(id: String, validateFunc: (Option[U], HawkRequest) => \/[HawkError, U]): Future[Either[HawkError, U]] = {
      val userTry = Try {
        // Assume the supplied userRetriever function can throw an exception
        userRetriever(id)
      }
      userTry match {
        case scala.util.Success(userFuture) =>
          userFuture map { validateFunc(_, hawkRequest) } map {
            case \/-(user) => Right(user)
            case -\/(error) => Left(error)
          }
        case scala.util.Failure(e) =>
          logger.warn(s"An error occurred while retrieving a hawk user: ${e.getMessage}")
          Future.successful(Left(UserRetrievalError(e)))
      }
    }

    // Determine whether to use bewit parameter or Authorization header
    // Request should not have both
    if (hawkRequest.hasBewit && hawkRequest.hasAuthorizationHeader) {
      Future.successful(Left(MultipleAuthenticationError))
    }
    else {
      // Ensure bewit is valid
      if (hawkRequest.hasBewit) {
        if (hawkRequest.bewitAttributes.isInvalid.isDefined) {
          Future.successful(Left(hawkRequest.bewitAttributes.isInvalid.get))
        }
        else validate(hawkRequest.bewitAttributes.id, validateBewitCredentials)
      }
      else {
        if (!hawkRequest.authHeaderAttributes.isPresent) {
          Future.successful(Left(CredentialsMissingError))
        }
        else validate(hawkRequest.authHeaderAttributes.id, validateAuthHeaderCredentials)
      }
    }
  }
}
