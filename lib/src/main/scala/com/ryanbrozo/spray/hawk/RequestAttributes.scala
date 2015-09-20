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

import spray.http.HttpHeaders.RawHeader
import spray.http.HttpRequest
import spray.http.Uri.Query

/**
 * RequestAttributes.scala
 *
 * Created by rye on 9/15/15.
 */
private[hawk] case class RequestAttributes(request: HttpRequest){

  private val xForwardedProtoHeader = request.headers.find {
    case h: RawHeader if h.lowercaseName == "x-forwarded-proto" => true
    case _ => false
  }

  private val rawUri = request.uri

  lazy val method: String = request.method.toString()
  lazy val host: String = rawUri.authority.host.toString.toLowerCase
  lazy val port: Int = rawUri.authority.port match {
    case i if i > 0 => i
    case 0 =>
      // Need to determine which scheme to use. Check if we have X-Forwarded-Proto
      // header set (usually by reverse proxies). Use this instead of original
      // scheme when present
      val scheme = xForwardedProtoHeader match {
        case Some(header) => header.value
        case None         => rawUri.scheme
      }
      scheme match {
        case "http"  => 80
        case "https" => 443
        case _       => 0
      }
  }
  lazy val uri: String = {
    // Spray URI separates path from additional query parameters
    // so we should append a '?' if query parameters are present
    rawUri.path.toString() + (rawUri.query match {
      case Query.Empty => ""
      case x: Query => s"?${x.toString()}"
    })
  }
}
