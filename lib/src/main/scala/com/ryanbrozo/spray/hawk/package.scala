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

import scala.concurrent.Future

package object hawk {

  /**
   * Authentication Scheme name
   */
  val HEADER_NAME = "Hawk"

  /**
   * Hawk Version
   */
  val HEADER_VERSION = 1

  /**
   * List of supported MAC algorithms. Passed as parameter
   * to javax.crypto.Mac.getInstance()
   */
  object MacAlgorithms extends Enumeration {
    val HmacSHA1, HmacSHA256 = Value
  }

  /**
   * List of supported hash algorithms. Passed as parameter
   * to `java.security.MessageDigest.getInstance()`
   */
  object HashAlgorithms extends Enumeration {
    val SHA1 = Value("SHA-1")
    val SHA256 = Value("SHA-256")
  }

  /**
   * Timestamp type
   */
  type TimeStamp = Long

  /**
   * Cryptographic Nonce. See this Wikipedia [[http://en.wikipedia.org/wiki/Cryptographic_nonce article]]
   */
  type Nonce = String

  /**
   * Data type representing a user's key identifier
   */
  type Key = String

  /**
   * App-specific data
   */
  type ExtData = String

  /**
   * Trait which represents a user entity with Hawk credentials. Modeled user entities
   * must implement this trait in order for authentication to work
   */
  trait HawkUser {
    val key: Key
    val algorithm: HawkHashAlgorithms
  }

  /**
   * Class representing a principal's Hawk credentials
   *
   * @param id Key identifier
   * @param key Key that will be used for calculating the MAC
   * @param algorithm Specific algorithm for calculating the MAC and payload hash. Should be
   *                  one of [[com.ryanbrozo.spray.hawk.HawkHashAlgorithms]]
   */
  case class HawkCredentials(id: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

  /**
   * List of parameters used for calculating MAC of a request
   */
  private[hawk] object HawkOptionKeys extends Enumeration {
    val Method, Uri, Host, Port, Ts, Nonce, Hash, Ext, App, Dlg = Value
  }

  private[hawk] type HawkOptions = Map[HawkOptionKeys.Value, String]

  private[hawk] type HawkAuthParams = Map[AuthHeaderKeys.Value, String]

  /**
   * Represents a function that retrieves a user object of type U
   * given an authenticated Hawk key identifier
   *
   * @tparam U Type of user to be retrieved. Should implement HawkUser trait
   */
  type UserRetriever[U <: HawkUser] = String => Future[Option[U]]

  /**
   * Represents a function that retrieves the current time expressed in
   * Unix time
   */
  type TimeStampProvider = () => TimeStamp

  /**
   * Represents a function that generates a random cryptographic nonce
   */
  type NonceProvider = () => Nonce

  /**
   * Represents a function that validates a nonce's uniqueness with the same timestamp and key identifier combination
   */
  type NonceValidator = (Nonce, Key, TimeStamp) => Boolean

}
