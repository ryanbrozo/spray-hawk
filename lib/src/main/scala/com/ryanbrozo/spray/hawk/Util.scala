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
import spray.http.HttpEntity.{Empty, NonEmpty}
import spray.http.HttpHeaders.RawHeader
import spray.http.HttpRequest
import spray.http.Uri.Query

import scala.compat.Platform
import scala.util.Random

/**
 * Util.scala
 *
 * Created by rye on 12/4/14 2:17 PM.
 */

private object Util {
  
  private val MINIMUM_NONCE_LENGTH = 6

  private val _conf = ConfigFactory.load()
  
  val nonceLength = {
    val v = _conf.getInt("spray.hawk.nonceLength")
    if (v < MINIMUM_NONCE_LENGTH) MINIMUM_NONCE_LENGTH else v
  }
  
}

trait Util {
  import Util._
  
  /**
   * Represents a function that extracts a parameter
   * from a map
   */
  type ParameterExtractor = HawkAuthKeys.Value => Option[String]

  /**
   * Produces an instance of [[com.ryanbrozo.spray.hawk.HawkOptions]] that will be used to verify the
   * Authorization header
   *
   * @param req Current [[spray.http.HttpRequest]]
   * @param extractor Extractor function that extracts hawk parameters from the Authorization header
   * @return Extracted options
   */
  def extractHawkOptions(req: HttpRequest, extractor: ParameterExtractor): HawkOptions = {
    val xForwardedProtoHeader = req.headers.find {
      case h: RawHeader if h.lowercaseName == "x-forwarded-proto" ⇒ true
      case _ ⇒ false
    }
    val ts = extractor(HawkAuthKeys.Ts).getOrElse("")
    val ext = extractor(HawkAuthKeys.Ext).getOrElse("")
    val nonce = extractor(HawkAuthKeys.Nonce).getOrElse("")
    val hashOption = extractor(HawkAuthKeys.Hash)
    val method = req.method.toString()
    val rawUri = req.uri

    // Spray URI separates path from additional query parameters
    // so we should append a '?' if query parameters are present
    val uri = rawUri.path.toString() + (rawUri.query match {
      case Query.Empty => ""
      case x: Query => s"?${x.toString()}"
    })
    val host = rawUri.authority.host.toString.toLowerCase
    val port = rawUri.authority.port match {
      case i if i > 0 => i
      case 0 ⇒
        // Need to determine which scheme to use. Check if we have X-Forwarded-Proto
        // header set (usually by reverse proxies). Use this instead of original
        // scheme when present
        val scheme = xForwardedProtoHeader match {
          case Some(header) => header.value
          case None         => rawUri.scheme
        }
        scheme match {
          case "http"  ⇒ 80
          case "https" ⇒ 443
          case _       ⇒ 0
        }
    }
    Map(
      HawkOptionKeys.Method -> Option(method),
      HawkOptionKeys.Uri -> Option(uri),
      HawkOptionKeys.Host -> Option(host),
      HawkOptionKeys.Port -> Option(port.toString),
      HawkOptionKeys.Ts -> Option(ts),
      HawkOptionKeys.Nonce -> Option(nonce),
      HawkOptionKeys.Ext -> Option(ext),
      HawkOptionKeys.Hash -> hashOption
    ).collect { case (k, Some(v)) => k -> v }
  }

  /**
   * Extracts payload information that is essential for Hawk payload validation from a request
   *
   * @param req [[HttpRequest]] instance, usually coming from the current Spray [[spray.routing.RequestContext]]
   * @return Payload data represented as byte array and it's corresponding Content-Type, wrapped as an [[Option]]
   */
  def extractPayload(req: HttpRequest): Option[(Array[Byte], String)] = {
    req.entity match {
      case e: NonEmpty =>
        val data = e.data.toByteArray
        val contentType = e.contentType.mediaType.toString()
        Some((data, contentType))
      case Empty => None
    }
  }

  /**
   * Default timestamp generator
   *
   * @return Current time in Unix Epoch
   */
  def generateTimestamp(): TimeStamp = Platform.currentTime / 1000

  /**
   * Default nonce generator
   *
   * @return Random string of length defined in the configuration file.
   */
  def generateNonce(): Nonce = Random.alphanumeric.take(nonceLength).mkString

}
