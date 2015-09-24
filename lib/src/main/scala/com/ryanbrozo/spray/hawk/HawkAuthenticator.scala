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

object HawkAuthenticator {
  
  abstract sealed class HawkRejection(val code: StatusCode,  val message: String) 

  case object InvalidUserRejection extends HawkRejection(StatusCodes.Unauthorized, "Unknown credentials")
  case object InvalidMacRejection extends HawkRejection(StatusCodes.Unauthorized, "Bad mac")
  case object InvalidPayloadHashRejection extends HawkRejection(StatusCodes.Unauthorized, "Bad payload hash")
  case object InvalidNonceRejection extends HawkRejection(StatusCodes.Unauthorized, "Invalid nonce")
  case object MultipleAuthenticationRejection extends HawkRejection(StatusCodes.BadRequest, "Multiple authentications")
  case object InvalidBewitEncodingRejection extends HawkRejection(StatusCodes.BadRequest, "Invalid bewit encoding")
  case object InvalidBewitStructureRejection extends HawkRejection(StatusCodes.BadRequest, "Invalid bewit structure")
  case object MissingBewitAttributesRejection extends HawkRejection(StatusCodes.BadRequest, "Missing bewit attributes")
  case object InvalidMethodRejection extends HawkRejection(StatusCodes.Unauthorized, "Invalid method")
  case object AccessExpiredRejection extends HawkRejection(StatusCodes.Unauthorized, "Access expired")
  case class StaleTimestampRejection(hawkUser: HawkUser) extends HawkRejection(StatusCodes.Unauthorized, "Stale timestamp")

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
  extends HttpAuthenticator[U]
  with StrictLogging {
  
  import HawkAuthenticator._

  val SCHEME = HEADER_NAME

  private def validateBewitCredentials(hawkUserOption: Option[U], hawkRequest: HawkRequest): \/[HawkRejection, Option[U]] = {
    def checkMethod(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      if (hawkRequest.request.method != HttpMethods.GET)
        InvalidMacRejection.left[Option[U]]
      else
        Option(hawkUser).right[HawkRejection]
    }

    def checkExpiry(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      val currentTimestamp = timestampProvider()
      if (hawkRequest.bewitAttributes.exp * 1000 <= currentTimestamp)
        AccessExpiredRejection.left[Option[U]]
      else
        Option(hawkUser).right[HawkRejection]
    }

    def checkMac(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      if (hawkRequest.bewitAttributes.mac != Hawk(hawkUser, hawkRequest.bewitOptions, Hawk.TYPE_BEWIT).mac)
        InvalidMacRejection.left[Option[U]]
      else
        Option(hawkUser).right[HawkRejection]
    }

    hawkUserOption map { implicit hawkUser =>
      for {
        methodOk <- checkMethod
        expiryOk <- checkExpiry
        macOk <- checkMac
      } yield expiryOk
    } getOrElse InvalidUserRejection.left[Option[U]]
  }

  private def validateAuthHeaderCredentials(hawkUserOption: Option[U], hawkRequest: HawkRequest): \/[HawkRejection, Option[U]] = {

    def checkMac(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      (for {
        mac <- hawkRequest.authHeaderAttributes.mac if mac == Hawk(hawkUser, hawkRequest.hawkOptions, Hawk.TYPE_HEADER).mac
      } yield Option(hawkUser).right[HawkRejection]) | InvalidMacRejection.left[Option[U]]
    }

    def checkPayload(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      hawkRequest.authHeaderAttributes.hash match {
        case Some(hash) if _payloadValidationEnabled =>
          // According to Hawk specs, payload validation should should only
          // happen if MAC is validated.
          (for {
            (payload, contentType) ← hawkRequest.payload
            hawkPayload ← Option(HawkPayload(payload, contentType, hawkUser.algorithm.hashAlgo))
            if hawkPayload.hash == hash
          } yield Option(hawkUser).right[HawkRejection]) | InvalidPayloadHashRejection.left[Option[U]]
        case _ =>
          // 'hash' is not supplied? then no payload validation is needed.
          // Return the obtained credentials
          Some(hawkUser).right[HawkRejection]
      }
    }

    def checkNonce(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      hawkRequest.authHeaderAttributes.nonce match {
        case Some(n) if nonceValidator(n, hawkUser.key, hawkRequest.authHeaderAttributes.ts) => Option(hawkUser).right[HawkRejection]
        case _ => InvalidNonceRejection.left[Option[U]]
      }
    }

    def checkTimestamp(implicit hawkUser: U): \/[HawkRejection, Option[U]] = {
      if (_timeSkewValidationEnabled) {
        val timestamp = hawkRequest.authHeaderAttributes.ts
        val currentTimestamp = timestampProvider()
        val lowerBound = currentTimestamp - _timeSkewInSeconds
        val upperBound = currentTimestamp + _timeSkewInSeconds
        if (lowerBound <= timestamp && timestamp <= upperBound)
          Option(hawkUser).right[HawkRejection]
        else
          StaleTimestampRejection(hawkUser).left[Option[U]]
      }
      else Option(hawkUser).right[HawkRejection]
    }

    hawkUserOption map { implicit hawkUser =>
      for {
        macOk <- checkMac
        payloadOk <- checkPayload
        nonceOk <- checkNonce
        tsOk <- checkTimestamp
      } yield tsOk
    } getOrElse InvalidUserRejection.left[Option[U]]
  }

  override def getChallengeHeaders(httpRequest: HttpRequest): List[HttpHeader] = {
    // Unfortunately, due to the design of spray.io, there is a need to
    // do all the validation again just to create the required WWW-Authenticate headers.
    // This can be costly, since we need to call the supplied userRetriever function again.
    // See https://github.com/spray/spray/issues/938 for more details

    val hawkRequest = HawkRequest(httpRequest)
    val userTry = Try {
      // Assume the supplied userRetriever function can throw an exception
      userRetriever(hawkRequest.authHeaderAttributes.id)
    }
    userTry match {
      case scala.util.Success(userFuture) =>
        val f = userFuture map { validateAuthHeaderCredentials(_, hawkRequest) } map {
          case -\/(err:StaleTimestampRejection) =>
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
        Await.result(f, _maxUserRetrieverTimeInSeconds)
      case scala.util.Failure(e) =>
        logger.warn(s"An error occurred while retrieving a hawk user: ${e.getMessage}")
        `WWW-Authenticate`(HttpChallenge(SCHEME, realm)) :: Nil
    }
  }

  override def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext): Future[Option[U]] = {
    val hawkRequest = HawkRequest(ctx.request)

    def validate(id: String, validateFunc: (Option[U], HawkRequest) => \/[HawkRejection, Option[U]]): Future[Option[U]] = {
      val userTry = Try {
        // Assume the supplied userRetriever function can throw an exception
        userRetriever(id)
      }
      userTry match {
        case scala.util.Success(userFuture) =>
          userFuture map { validateFunc(_, hawkRequest) } map {
            case \/-(user) => user
            case _ => None
          }
        case scala.util.Failure(e) =>
          logger.warn(s"An error occurred while retrieving a hawk user: ${e.getMessage}")
          Future.successful(None)
      }
    }

    // Determine whether to use bewit parameter or Authorization header
    // Request should not have both
    if (hawkRequest.hasBewit && hawkRequest.hasAuthorizationHeader) {
      // TODO: Find a way to return MultipleAuthenticationRejection
      Future.successful(None)
    }
    else {
      // Ensure bewit is valid
      if (hawkRequest.hasBewit) {
        if (!hawkRequest.bewitAttributes.isValid.isRight) {
          // TODO: Find a way to return bewit validation rejection
          Future.successful(None)
        }
        else validate(hawkRequest.bewitAttributes.id, validateBewitCredentials)
      }
      else validate(hawkRequest.authHeaderAttributes.id, validateAuthHeaderCredentials)
    }
  }
}
