/*
 *
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

import com.typesafe.config.ConfigFactory
import spray.http.HttpHeaders.RawHeader
import spray.http.{HttpHeaders, HttpRequest, HttpResponse}
import spray.routing.Directives._
import spray.routing.{RejectionHandler, Directive0}
import spray.routing.directives.BasicDirectives

import scala.concurrent._
import scala.concurrent.duration._
import scala.language.{implicitConversions, postfixOps}
import scala.util.Try

/**
 * Magnet used to construct our route directives. See http://spray.io/blog/2012-12-13-the-magnet-pattern/ for more info
 *
 */
private[hawk] sealed trait HawkRouteDirectivesMagnet {
  type Out

  def apply(): Out
}

private[hawk] object HawkRouteDirectivesMagnet
  extends BasicDirectives
  with Util {

  private val _conf = ConfigFactory.load()

  private[hawk] val _serverAuthorizationExt = _conf.getString("spray.hawk.serverAuthorizationExt")
  private[hawk] val _maxUserRetrieverTimeInSeconds = _conf.getLong("spray.hawk.maxUserRetrieverTimeInSeconds") seconds

  private def generateServerAuthHeader(request: HttpRequest, response: HttpResponse, ext: ExtData, credentials: HawkUser): RawHeader = {
    // Compute 'hash' param?
    val payloadHashOption = extractPayload(response) map {
      case (payload, contentType) => HawkPayload(payload, contentType, credentials.algorithm.hashAlgo).hash
    }

    val hawkRequest = HawkRequest(request)

    // Replace the ext and hash options. See https://github.com/hueniverse/hawk#response-payload-validation
    val updatedOptions = hawkRequest.hawkOptions
      .updated(HawkOptionKeys.Ext, ext)
      .updated(HawkOptionKeys.Hash, payloadHashOption.getOrElse(""))

    // Compute our MAC
    val mac = Hawk(credentials, updatedOptions, Hawk.TYPE_RESPONSE).mac

    // Then create our Hawk Authorization header
    val authHeader = Map(
      AuthHeaderKeys.Mac -> Option(mac),
      AuthHeaderKeys.Hash -> payloadHashOption,
      AuthHeaderKeys.Ext -> Option(ext)
    )
      .collect({ case (k, Some(v)) => k.toString + "=" + "\"" + v + "\"" })
      .mkString(", ")

    HttpHeaders.RawHeader("Server-Authorization", s"$HEADER_NAME $authHeader")
  }

  implicit def fromUserRetriever[U <: HawkUser](userRetriever: UserRetriever[U])(implicit executionContext: ExecutionContext) = new HawkRouteDirectivesMagnet {
    type Out = Directive0

    override def apply(): Out = mapRequestContext { ctx =>
      ctx.withHttpResponseMapped { resp =>
        val hawkRequest = HawkRequest(ctx.request)
        val userTry = Try {
          // Assume the supplied userRetriever function can throw an exception
          userRetriever(hawkRequest.authHeaderAttributes.id)
        }
        userTry match {
          case scala.util.Success(userFuture) =>
            val f = userFuture map {
              case Some(user) =>
                val serverAuthHeader = generateServerAuthHeader(ctx.request, resp, _serverAuthorizationExt, user)
                resp.mapHeaders(serverAuthHeader :: _)
              case None => resp
            }
            Await.result(f, _maxUserRetrieverTimeInSeconds)
          case scala.util.Failure(e) =>
            resp
        }
      }
    }
  }
}

/**
 * Contains directives that are used with `spray-routing` to produce Hawk-Authenttication specific request and response transformations
 */
trait HawkRouteDirectives {

  implicit val hawkRejectionHandler = RejectionHandler {
    case HawkRejection(error, _) :: _ =>
      complete(error.code, error.message)
  }

  /**
   * Adds a Server-Authorization header to the responses. This header is provided so it can be validated whether clients are talking to
   * the right server. See the [[https://github.com/hueniverse/hawk#response-payload-validation Response Payload Validation]] section of
   * Hawk's specification more more details
   *
   * {{{
// Our User model. This needs to extend the HawkUser trait for our UserCredentialsRetriever
// to work
case class User(name: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

// Our user credentials retriever. Currently it returns 'Bob' along with his hawk credentials
val userCredentialsRetriever: UserRetriever[User] = { id =>
    Future.successful {
      if (id == "dh37fgj492je") Some(User("Bob", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256))
      else None
    }
}

val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)

startServer(interface = "localhost", port = 8080) {
  // Add Server-Authorization header for response payload validation
  withHawkServerAuthHeader(userCredentialsRetriever) {
    path("secured") {
      authenticate(hawkAuthenticator) { user =>
        get {
          complete {
            s"Welcome to spray, \${user.name}!"
          }
        } ~
        post {
          entity(as[String]) { body =>
            complete {
              s"Welcome to spray, \${user.name}! Your post body was: \$body"
            }
          }
        }
      }
    }
  }
}
   * }}}
   *
   * @param magnet User-retriver function conforming to [[UserRetriever]]
   */
  def withHawkServerAuthHeader(magnet: HawkRouteDirectivesMagnet) = magnet()
}
