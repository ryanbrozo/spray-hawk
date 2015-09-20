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

import spray.http.HttpEntity.{Empty, NonEmpty}
import spray.http.{HttpMessage, HttpResponse, HttpRequest}

/**
 * HawkRequest.scala
 *
 * Created by rye on 9/15/15.
 */
case class HawkRequest(request: HttpRequest, withPayloadValidation: Boolean = true)
  extends Util {

  lazy val requestAttributes: RequestAttributes = RequestAttributes(request)
  lazy val authHeaderAttributes: AuthHeaderAttributes = AuthHeaderAttributes(request)
  lazy val providedOptions: HawkOptions = {
    Map(
      HawkOptionKeys.Method -> Option(requestAttributes.method),
      HawkOptionKeys.Uri -> Option(requestAttributes.uri),
      HawkOptionKeys.Host -> Option(requestAttributes.host),
      HawkOptionKeys.Port -> Option(requestAttributes.port.toString),
      HawkOptionKeys.Ts -> Option(authHeaderAttributes.ts.toString),
      HawkOptionKeys.Nonce -> authHeaderAttributes.nonce,
      HawkOptionKeys.Ext -> authHeaderAttributes.ext,
      HawkOptionKeys.Hash -> authHeaderAttributes.hash).collect { case (k, Some(v)) => k -> v }
  }

  lazy val payload: Option[(Array[Byte], String)] = extractPayload(request)
}

