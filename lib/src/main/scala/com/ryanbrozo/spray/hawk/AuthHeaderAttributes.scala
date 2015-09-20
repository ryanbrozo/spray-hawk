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

import spray.http.HttpHeaders.{Authorization, RawHeader}
import spray.http.{GenericHttpCredentials, HttpRequest}
import spray.http.Uri.Query
import spray.util._





private[hawk] case class AuthHeaderAttributes(request: HttpRequest) {
  import AuthHeaderKeys._

  private val authHeader = request.headers.findByType[`Authorization`]
  private val credentials = authHeader.map {
    case Authorization(creds) => creds
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
  private def extractAuthKey(credentials: GenericHttpCredentials)(key: AuthHeaderKeys.Value): Option[String] =
    credentials.params.get(key.toString)

  lazy val id: String = extractor flatMap {_(Id)} getOrElse ""
  private lazy val tsOption: Option[String] = extractor flatMap {_(Ts)}
  lazy val ts: TimeStamp = tsOption map {_.toLong} getOrElse 0
  lazy val nonce: Option[Nonce] = extractor flatMap {_(Nonce)}
  lazy val hash: Option[String] = extractor flatMap {_(Hash)}
  lazy val ext: Option[ExtData] = extractor flatMap {_(Ext)}
  lazy val mac: Option[String] = extractor flatMap {_(Mac)}
}

