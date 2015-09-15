/*
 *
 *  * The MIT License (MIT)
 *  *
 *  * Copyright (c) 2015 Ryan C. Brozo
 *  *
 *  * Permission is hereby granted, free of charge, to any person obtaining a copy
 *  * of this software and associated documentation files (the "Software"), to deal
 *  * in the Software without restriction, including without limitation the rights
 *  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  * copies of the Software, and to permit persons to whom the Software is
 *  * furnished to do so, subject to the following conditions:
 *  *
 *  * The above copyright notice and this permission notice shall be included in all
 *  * copies or substantial portions of the Software.
 *  *
 *  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  * SOFTWARE.
 *
 */

package com.ryanbrozo.spray.hawk

import com.ryanbrozo.spray.hawk.Util._
import spray.http.HttpHeaders.RawHeader
import spray.http.{HttpHeaders, HttpRequest, HttpResponse}
import spray.routing.Directive0
import spray.routing.directives.BasicDirectives

import scala.concurrent._
import scala.concurrent.duration._
import scala.language.{implicitConversions, postfixOps}
import scala.util.Try

/**
 * HawkRouteDirectives.scala
 *
 * Created by rye on 9/10/15.
 */

sealed trait HawkRouteDirectivesMagnet {
  type Out

  def apply(): Out
}

object HawkRouteDirectivesMagnet
  extends BasicDirectives
  with Util {

  private def generateServerAuthHeader(request: HttpRequest, response: HttpResponse, id: String, timestampProvider: TimeStampProvider,
                                       nonceProvider: NonceProvider, ext: ExtData, credentials: HawkUser): RawHeader = {
    // Do we need to compute 'hash' param?
    val payloadHashOption =
      extractPayload(response) map {
        case (payload, contentType) => HawkPayload(payload, contentType, credentials.algorithm.hashAlgo).hash
      }

    // First, let's extract URI-related hawk options
    val hawkOptions = extractHawkOptions(request, response, { _ => None })

    // Then add our user-specified parameters
    val ts = timestampProvider().toString
    val nonce = nonceProvider()
    val updatedOptions = hawkOptions ++ Map(
      HawkOptionKeys.Ts -> Option(ts),
      HawkOptionKeys.Nonce -> Option(nonce),
      HawkOptionKeys.Ext -> Option(ext),
      HawkOptionKeys.Hash -> payloadHashOption
    ).collect { case (k, Some(v)) => k -> v }

    // Compute our MAC
    val mac = Hawk(credentials, updatedOptions, Hawk.TYPE_RESPONSE).mac

    // Then create our Hawk Authorization header
    val authHeader = Map(
      HawkAuthKeys.Id -> Option(id),
      HawkAuthKeys.Ts -> Option(ts),
      HawkAuthKeys.Nonce -> Option(nonce),
      HawkAuthKeys.Ext -> Option(ext),
      HawkAuthKeys.Mac -> Option(mac),
      HawkAuthKeys.Hash -> payloadHashOption
    )
      .collect({ case (k, Some(v)) => k.toString + "=" + "\"" + v + "\"" })
      .mkString(",")

    HttpHeaders.RawHeader("Server-Authorization", s"Hawk $authHeader")
  }

  implicit def fromUserRetriever[U <: HawkUser](userRetriever: UserRetriever[U])(implicit executionContext: ExecutionContext) = new HawkRouteDirectivesMagnet {
    type Out = Directive0

    override def apply(): Out = mapRequestContext { ctx =>
      ctx.withHttpResponseMapped { resp =>
        val hawkHttpCredentials = HawkHttpCredentials(ctx.request)
        val userTry = Try {
          // Assume the supplied userRetriever function can throw an exception
          userRetriever(hawkHttpCredentials.id)
        }
        userTry match {
          case scala.util.Success(userFuture) =>
            val f = userFuture map {
              case Some(user) =>
                val serverAuthHeader = generateServerAuthHeader(ctx.request, resp, hawkHttpCredentials.id, Util.defaultTimestampProvider,
                  Util.defaultNonceGenerator, "server", user)
                resp.mapHeaders(serverAuthHeader :: _)
              case None => resp
            }
            Await.result(f, 60 seconds)
          case scala.util.Failure(e) =>
            resp
        }
      }
    }
  }
}

trait HawkRouteDirectives {
  def withHawkServerAuthHeader(magnet: HawkRouteDirectivesMagnet) = magnet()
}
