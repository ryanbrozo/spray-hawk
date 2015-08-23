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

import spray.http.{HttpRequest, GenericHttpCredentials}
import spray.http.HttpHeaders.{Authorization, RawHeader}
import spray.http.Uri.Query
import spray.util._

/**
 * HawkHttpCredentials.scala
 *
 * Created by rye on 8/22/15.
 */
case class HawkHttpCredentials(request: HttpRequest) {
  import HawkAuthKeys._

  private val authHeader = request.headers.findByType[`Authorization`]
  private val credentials = authHeader.map {
    case Authorization(creds) ⇒ creds
  } flatMap {
    case creds: GenericHttpCredentials => Option(creds)
    case _ => None
  }

  private val extractor = credentials map extractAuthKey

  /**
   * Extracts a key from the Authorization header
   *
   * @param credentials Authorization header represented as [[spray.http.GenericHttpCredentials]]
   * @param key Key of value to obtain
   * @return Extracted value wrapped as a [[scala.Option]]
   */
  private def extractAuthKey(credentials: GenericHttpCredentials)(key: HawkAuthKeys.Value): Option[String] =
    credentials.params.get(key.toString)

  private val xForwardedProtoHeader = request.headers.find {
    case h: RawHeader if h.lowercaseName == "x-forwarded-proto" ⇒ true
    case _ ⇒ false
  }

  private val rawUri = request.uri

  lazy val id: String = extractor flatMap {_(Id)} getOrElse ""
  private lazy val tsOption: Option[String] = extractor flatMap {_(Ts)}
  lazy val ts: TimeStamp = tsOption map {_.toLong} getOrElse 0
  lazy val nonce: Option[Nonce] = extractor flatMap {_(Nonce)}
  lazy val ext: Option[ExtData] = extractor flatMap {_(Ext)}
  lazy val app: Option[String] = extractor flatMap {_(App)}
  lazy val dlg: Option[String] = extractor flatMap {_(Dlg)}
  lazy val mac: Option[String] = extractor flatMap {_(Mac)}
  lazy val hash: Option[String] = extractor flatMap {_(Hash)}
  lazy val method: String = request.method.toString()

  lazy val uri: String = {
    // Spray URI separates path from additional query parameters
    // so we should append a '?' if query parameters are present
    rawUri.path.toString() + (rawUri.query match {
      case Query.Empty ⇒ ""
      case x: Query ⇒ s"?${x.toString()}"
    })
  }

  lazy val host: String = rawUri.authority.host.toString.toLowerCase
  lazy val port: Int = rawUri.authority.port match {
    case i if i > 0 ⇒ i
    case 0 ⇒
      // Need to determine which scheme to use. Check if we have X-Forwarded-Proto
      // header set (usually by reverse proxies). Use this instead of original
      // scheme when present
      val scheme = xForwardedProtoHeader match {
        case Some(header) ⇒ header.value
        case None         ⇒ rawUri.scheme
      }
      scheme match {
        case "http"  ⇒ 80
        case "https" ⇒ 443
        case _       ⇒ 0
      }
  }

  lazy val options: HawkOptions = Map(
    HawkOptionKeys.Method -> Option(method),
    HawkOptionKeys.Uri -> Option(uri),
    HawkOptionKeys.Host -> Option(host),
    HawkOptionKeys.Port -> Option(port.toString),
    HawkOptionKeys.Ts -> Option(tsOption.getOrElse("")),
    HawkOptionKeys.Nonce -> Option(nonce.getOrElse("")),
    HawkOptionKeys.Ext -> Option(ext.getOrElse("")),
    HawkOptionKeys.Hash -> hash
  ).collect { case (k, Some(v)) ⇒ k -> v }
}
