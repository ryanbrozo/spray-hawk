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

package com.ryanbrozo.spray

package object hawk {

  /**
   * List of supported MAC algorithms. Passed as parameter
   * to javax.crypto.Mac.getInstance()
   */
  object Algorithms extends Enumeration {
    val HmacMD5, HmacSHA1, HmacSHA256 = Value
  }

  /**
   * Case class representing a principal's Hawk credentials
   *
   * @param key Key that will be used for calculating the MAC
   * @param algorithm Specific algorithm for calculating the MAC. Should be
   *                    one of [[com.ryanbrozo.spray.hawk.Algorithms]]
   */
  case class HawkCredentials(key: String, algorithm: Algorithms.Value)

  /**
   * List of parameters used for calculating MAC of a request
   */
  object HawkParameters extends Enumeration {
    val Method, Uri, Host, Port, Ts, Nonce, Hash, Ext, App, Dlg = Value
  }

  type HawkOptions = Map[HawkParameters.Value, String]

}
