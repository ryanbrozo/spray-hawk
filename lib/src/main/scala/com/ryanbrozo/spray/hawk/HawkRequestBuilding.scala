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
import spray.http.HttpHeaders
import spray.httpx.RequestBuilding

/**
 * HawkRequestBuilding.scala
 *
 * Created by rye on 12/4/14 2:01 PM.
 */
trait HawkRequestBuilding extends RequestBuilding with Util {

  /**
   * Adds a Hawk Authorization header to a request
   *
   * @param credentials Hawk credentials
   * @param ts Current timestamp
   * @param nonce Random cryptographic nonce. See this Wikipedia [[http://en.wikipedia.org/wiki/Cryptographic_nonce article]]
   * @param ext App-specific data
   * @return
   */
  def addHawkCredentials(credentials: HawkCredentials)(implicit ts: TimeStamp, nonce: Nonce, ext: ExtData): RequestTransformer = {request =>
    // First, let's extract URI-related hawk options
    extractHawkOptions(request, { _ => None }).map ({ hawkOptions =>
      // Then, add, user-specified parameters
      val updatedOptions = hawkOptions ++ Map(
        HawkOptionKeys.Ts -> ts.toString,
        HawkOptionKeys.Nonce -> nonce,
        HawkOptionKeys.Ext -> ext
      )
      // Compute our MAC
      val mac = Hawk(credentials, updatedOptions).mac

      // Then create our Hawk Authorization header
      val authHeader = Map(
        HawkAuthKeys.Id -> credentials.id,
        HawkAuthKeys.Ts -> ts,
        HawkAuthKeys.Nonce -> nonce,
        HawkAuthKeys.Ext -> ext,
        HawkAuthKeys.Mac -> mac
      ).map({case (k, v) => k.toString + "=" + "\"" + v + "\""})
      .mkString(",")

      // Add it to the current request
      request.mapHeaders(HttpHeaders.RawHeader("Authorization", s"Hawk $authHeader") :: _)
    }).getOrElse(request)
  }
}
