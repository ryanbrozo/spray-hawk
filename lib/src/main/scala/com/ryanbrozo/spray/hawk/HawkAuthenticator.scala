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
import spray.http.HttpHeaders._
import spray.http._
import spray.routing.RequestContext
import spray.routing.authentication.HttpAuthenticator

import scala.concurrent.{ExecutionContext, Future}

private object HawkAuthenticator {
  
  private val _conf = ConfigFactory.load()
  
  val payloadValidationEnabled = _conf.getBoolean("spray.hawk.payloadValidation")
  
}

/**
 * A HawkAuthenticator is a ContextAuthenticator that uses credentials passed to the server via the
 * HTTP `Authorization` header to authenticate the user and extract a user object.
 *
 */
case class HawkAuthenticator[U <: HawkUser](realm: String,
                                userRetriever: UserRetriever[U])
                               (implicit val executionContext: ExecutionContext)
  extends HttpAuthenticator[U]
  with Util {
  
  import HawkAuthenticator._

  val SCHEME = "Hawk"

  /**
   * Extracts a key from the Authorization header
   *
   * @param credentials Authorization header represented as [[spray.http.GenericHttpCredentials]]
   * @param key Key of value to obtain
   * @return Extracted value [[scala.Option]]
   */
  private def extractAuthKey(credentials: GenericHttpCredentials)(key: HawkAuthKeys.Value): Option[String] =
    credentials.params.get(key.toString)

  override def getChallengeHeaders(httpRequest: HttpRequest): List[HttpHeader] =
    `WWW-Authenticate`(HttpChallenge(SCHEME, realm, params = Map.empty)) :: Nil

  override def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext): Future[Option[U]] = {
    import HawkAuthKeys._

    val userFuture: Option[Future[Option[U]]] = for {
      creds@(_a: GenericHttpCredentials) <- credentials
      id <- extractAuthKey(creds)(Id)
      mac <- extractAuthKey(creds)(Mac)
      hawkOptions <- Option(extractHawkOptions(ctx.request, extractAuthKey(creds)))
    } yield {
      userRetriever(id) flatMap {
        case Some(hawkCreds) =>
          val calculatedMac = Hawk(hawkCreds, hawkOptions).mac
          if (calculatedMac == mac) {
            val result = hawkOptions.get(HawkOptionKeys.Hash).fold{
              // 'hash' is not supplied? then no payload validation is needed.
              // Return the obtained credentials
              Option(hawkCreds)
            }{ hash =>
              if (payloadValidationEnabled) {
                // According to Hawk specs, payload validation should should only
                // happen if MAC is validated.
                for {
                  (payload, contentType) <- extractPayload(ctx.request)
                  hawkPayload <- Option(HawkPayload(payload, contentType, hawkCreds.algorithm.hashAlgo))
                  if hawkPayload.hash == hash
                } yield hawkCreds
              }
              else Option(hawkCreds)
            }
            Future.successful(result)
          }
          else
            Future.successful(None)
        case _ =>
          Future.successful(None)
      }
    }
    userFuture.getOrElse(Future.successful(None))
  }
}
