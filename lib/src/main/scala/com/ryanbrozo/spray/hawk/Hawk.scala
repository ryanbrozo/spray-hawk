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

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.parboiled.common.Base64

/**
 * Calculates MAC given the options passed to it
 * *
 * @param options List of parameters to be used for computing the MAC
 *                The following options are mandatory:
 *
 *                Method - HTTP request method (i.e. GET, POST, PUT, etc)
 *                Uri - Request URI
 *                Host - Host name
 *                Port - Port number
 *                Ts - Current timestamp
 *                Nonce - Arbitrary random text
 *
 *                Optional parameters
 *
 *                Ext - Application-specific data
 *                App - Application Id
 *                Dlg - Delegated by application id (Oz), requires App
 *
 *                If payload validation is used, the following options should be
 *                supplied:
 *
 *                Hash - Hash of payload as described [[https://github.com/hueniverse/hawk#payload-validation here]]
 *
 * @param payload Optional payload data if Hawk MAC calculation should use payload validation
 *
 */
case class Hawk(credentials: HawkUser, options: HawkOptions, payload: Option[HawkPayload] = None) {

  /**
   * Normalized string that will be used for calculating the MAC
   */
  lazy val normalized: String = {
    import com.ryanbrozo.spray.hawk.HawkOptionKeys._

    val appDlg = for (app <- options.get(App); dlg <- options.get(Dlg)) yield s"$app\n$dlg\n"
//    val hash = payload match {
//      case Some(p) => p.hash
//      case None => ""
//    }

    s"""hawk.$HEADER_VERSION.header
      |${options.getOrElse(Ts, "")}
      |${options.getOrElse(Nonce, "")}
      |${options.getOrElse(Method, "")}
      |${options.getOrElse(Uri, "")}
      |${options.getOrElse(Host, "")}
      |${options.getOrElse(Port, "")}
      |${options.getOrElse(Hash, "")}
      |${options.getOrElse(Ext, "")}
      |${appDlg.getOrElse("")}""".stripMargin
  }

  /**
   * Calculated MAC
   */
  lazy val mac: String = {
    val mac = Mac.getInstance(credentials.algorithm.hmac.toString)
    mac.init(new SecretKeySpec(credentials.key.getBytes("UTF-8"), credentials.algorithm.hmac.toString))
    Base64.rfc2045().encodeToString(mac.doFinal(normalized.getBytes("UTF-8")), false)
  }
}
