/*
 *
* The MIT License (MIT)
*
* Copyright (c) 2015 Ryan C. Brozo
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
 *
 */

package com.ryanbrozo.spray.hawk

sealed trait HawkHashAlgorithms {
  val hmacAlgo: MacAlgorithms.Value
  val hashAlgo: HashAlgorithms.Value
}

object HawkHashAlgorithms {
  /**
   * Used to specify SHA1 as the algorithm to use for encryption of a user's credentials
   */
  case object HawkSHA1 extends HawkHashAlgorithms { val hmacAlgo = MacAlgorithms.HmacSHA1; val hashAlgo = HashAlgorithms.SHA1 }

  /**
   * Used to specify SHA256 as the algorithm to use for encryption of a user's credentials
   */
  case object HawkSHA256 extends HawkHashAlgorithms { val hmacAlgo = MacAlgorithms.HmacSHA256; val hashAlgo = HashAlgorithms.SHA256 }
}
