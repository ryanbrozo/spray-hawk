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

import com.typesafe.config.ConfigFactory
import com.typesafe.scalalogging.StrictLogging
import spray.caching.ExpiringLruCache
import spray.http.HttpEntity.{Empty, NonEmpty}
import spray.http.Uri.Query
import spray.http._

import scala.compat.Platform
import scala.concurrent.duration._
import scala.language.{implicitConversions, postfixOps}
import scala.util.Random

/**
  * Helper functions
  */

object Util {

  private val MINIMUM_NONCE_LENGTH = 6

  private val _conf = ConfigFactory.load()

  private val _nonceLength = {
    val v = _conf.getInt("spray.hawk.nonceLength")
    if (v < MINIMUM_NONCE_LENGTH) MINIMUM_NONCE_LENGTH else v
  }

  private val _maxCacheCapacity = _conf.getInt("spray.hawk.cachingNonceValidator.maximumCapacity")
  private val _initialCacheCapacity = _conf.getInt("spray.hawk.cachingNonceValidator.initialCapacity")

  // TTL and TTI setting is derived from time skew settings. This value will be multiplied by 2
  // to accommodate period left and right of the current time
  private val _timeToIdleInSeconds = (_conf.getInt("spray.hawk.timeSkewInSeconds") * 2) seconds
  private val _timeToLiveInSeconds= _timeToIdleInSeconds + (1 second)

  private val _cache = new ExpiringLruCache[TimeStamp](_maxCacheCapacity, _initialCacheCapacity, _timeToLiveInSeconds, _timeToIdleInSeconds)

  /**
   * Default nonce validator. Uses an in-memory cache to validate nonces
   *
   * @param nonce Nonce to valiaate
   * @param key Key identifier
   * @param ts timestamp
   * @return True, if nonce is valid. False, if not
   */
  def defaultNonceValidator(nonce: Nonce, key: Key, ts: TimeStamp): Boolean = {
    import scala.concurrent.ExecutionContext.Implicits.global

    val cacheKey = s"${nonce}_${key}_$ts"
    _cache.get(cacheKey) match {
      case Some(_) =>
        // Nonce-key-ts combination exists, which means these have been
        // used in a previous request
        false
      case None =>
        _cache(cacheKey){ts}
        true
    }
  }

  /**
   * Default timestamp generator
   *
   * @return Current time in Unix Epoch
   */
  def defaultTimestampProvider(): TimeStamp = Platform.currentTime / 1000

  /**
   * Default nonce generator
   *
   * @return Random string of length defined in the configuration file.
   */
  def defaultNonceGenerator(): Nonce = Random.alphanumeric.take(_nonceLength).mkString

  /**
   * Non-validating nonce validator (wut?). Doesn't really validate nonces and just returns True
   *
   * @param nonce Nonce to valiaate
   * @param key Key identifier
   * @param ts timestamp
   * @return True everytime
   */
  def stupidNonceValidator(nonce: Nonce, key: Key, ts: TimeStamp): Boolean = true
}

private[hawk] trait Util extends StrictLogging {

  /**
    * Extracts payload information that is essential for Hawk payload validation from a message
    *
    * @param req Spray HttpMessage instance, usually coming from the current Spray RequestContext
    * @return Payload data represented as byte array and it's corresponding Content-Type, wrapped as an Option
    */
  private[hawk] def extractPayload(req: HttpMessage): Option[(Array[Byte], String)] = {
    req.entity match {
      case e: NonEmpty =>
        val data = e.data.toByteArray
        val contentType = e.contentType.mediaType.toString()
        Some((data, contentType))
      case Empty => None
    }
  }

  private[hawk] def extractUriString(uri: Uri): String = {
    // Spray URI separates path from additional query parameters
    // so we should append a '?' if query parameters are present
    uri.path.toString() + (uri.query match {
      case Query.Empty => ""
      case x: Query => s"?${x.toString()}"
    })
  }

}
