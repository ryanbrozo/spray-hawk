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

import spray.http.HttpHeaders._
import spray.http.Uri.Query
import spray.http._
import spray.routing.RequestContext
import spray.routing.authentication.HttpAuthenticator

import scala.concurrent.{ExecutionContext, Future}

/**
 * A HawkAuthenticator is a ContextAuthenticator that uses credentials passed to the server via the
 * HTTP `Authorization` header to authenticate the user and extract a user object.
 */
case class HawkAuthenticator[U](realm: String,
                                hawkCredentialsRetriever: HawkCredentialsRetriever,
                                 userRetriever: UserRetriever[U])
                               (implicit val executionContext: ExecutionContext)
  extends HttpAuthenticator[U] {

  val SCHEME = "Hawk"

  /**
   * Extracts a key from the Authorization header
   *
   * @param credentials Authorization header represented as [[spray.http.GenericHttpCredentials]]
   * @param key Key of value to obtain
   * @return Extracted value [[scala.Option]]
   */
  private def extractAuthKey(credentials: GenericHttpCredentials)(key: String): Option[String] = credentials.params.get(key)

  /**
   * Produces an instance of [[com.ryanbrozo.spray.hawk.HawkOptions]] that will be used to verify the
   * Authorization header
   *
   * @param ctx Current [[spray.routing.RequestContext]]
   * @param credentials Authorization header represented as [[spray.http.GenericHttpCredentials]]
   * @return Extracted options
   */
  private def extractHawkOptions(ctx: RequestContext, credentials: GenericHttpCredentials): Option[HawkOptions] = {
    val xForwardedProtoHeader = ctx.request.headers.find {
      case h: RawHeader if h.lowercaseName == "x-forwarded-proto" ⇒ true
      case _ ⇒ false
    }
    val extractor = extractAuthKey(credentials) _
    val ts = extractor("ts").getOrElse("")
    val ext = extractor("ext").getOrElse("")
    val nonce = extractor("nonce").getOrElse("")
    val method = ctx.request.method.toString()
    val rawUri = ctx.request.uri

    // Spray URI separates path from additional query parameters
    // so we should append a '?' if query parameters are present
    val uri = rawUri.path.toString() + (rawUri.query match {
      case Query.Empty => ""
      case x: Query => s"?${x.toString()}"
    })
    val host = rawUri.authority.host.toString.toLowerCase
    val port = rawUri.authority.port match {
      case i if i > 0 => i
      case 0 ⇒
        // Need to determine which scheme to use. Check if we have X-Forwarded-Proto
        // header set (usually by reverse proxies). Use this instead of original
        // scheme when present
        val scheme = xForwardedProtoHeader match {
          case Some(header) => header.value
          case None         => rawUri.scheme
        }
        scheme match {
          case "http"  ⇒ 80
          case "https" ⇒ 443
          case _       ⇒ 0
        }
    }
    Some(Map(
      HawkOptionKeys.Method -> method,
      HawkOptionKeys.Uri -> uri,
      HawkOptionKeys.Host -> host,
      HawkOptionKeys.Port -> port.toString,
      HawkOptionKeys.Ts -> ts,
      HawkOptionKeys.Nonce -> nonce,
      HawkOptionKeys.Ext -> ext
    ))
  }

  /**
   * Extracts the payload data for Hawk hash computation
   * @param ctx Current [[spray.routing.RequestContext]]
   * @return [[com.ryanbrozo.spray.hawk.HawkPayload]] data
   */
  private def extractHawkPayload(ctx: RequestContext): HawkPayload = ???

  override def getChallengeHeaders(httpRequest: HttpRequest): List[HttpHeader] =
    `WWW-Authenticate`(HttpChallenge(SCHEME, realm, params = Map.empty)) :: Nil

  override def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext): Future[Option[U]] = {
    val userFuture: Option[Future[Option[U]]] = for {
      creds@(_a: GenericHttpCredentials) <- credentials
      id <- extractAuthKey(creds)("id")
      mac <- extractAuthKey(creds)("mac")
      hawkOptions <- extractHawkOptions(ctx, creds)
    } yield {
      hawkCredentialsRetriever(id) flatMap {
        case Some(hawkCreds) if Hawk(hawkCreds, hawkOptions).mac == mac =>
          userRetriever(Some(hawkCreds.id))
        case _ =>
          userRetriever(None)
      }
    }
    userFuture.getOrElse(userRetriever(None))
  }
}
