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

import com.ryanbrozo.spray.hawk.Util._
import spray.http.HttpHeaders.RawHeader
import spray.http.{HttpHeaders, HttpRequest}
import spray.httpx.RequestBuilding


/**
 * A Spray RequestBuilding trait which is mixed in to a spray-client app to provide Hawk authentication support for requests.
 *
 * Example usage:
 *
 * {{{
object HawkClient extends App with HawkRequestBuilding {

  implicit val system = ActorSystem("hawk-client")

  //Execution context for futures
  import system.dispatcher

  val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkSHA256)

  val pipeline =
    addHawkCredentials("hawk-client")(hawkCreds, withPayloadValidation = true) ~>
    sendReceive ~>
    unmarshal[String]

  val responseFuture = pipeline {
    Get("http://localhost:8080/secured")
  }

  responseFuture onComplete {
    case Success(result) =>
      println(result)
      shutdown()
    case util.Failure(error) =>
      println(s"Cannot retrieve URL: \$error")
      shutdown()
  }
}
 * }}}
 *
 *
 */
trait HawkRequestBuilding extends RequestBuilding with Util {

  /**
   * Adds a Hawk Authorization header to a request
   *
   * @param credentials Hawk credentials
   * @param timestampProvider Function to generate current timestamp
   * @param nonceProvider Function to generate random cryptographic nonce
   * @param ext App-specific data
   * @return
   */
  protected def generateRawHeader(request: HttpRequest, timestampProvider: TimeStampProvider, nonceProvider: NonceProvider, ext: ExtData,
                                  credentials: HawkCredentials, withPayloadValidation: Boolean): RawHeader = {
    // Do we need to compute 'hash' param?
    val payloadHashOption = if (withPayloadValidation) {
      extractPayload(request) map {
        case (payload, contentType) => HawkPayload(payload, contentType, credentials.algorithm.hashAlgo).hash
      }
    } else None

    // First, let's extract URI-related hawk options
    val hawkOptions = extractHawkOptions(request, request,  { _ => None })

    // Then add our user-specified parameters
    val ts = timestampProvider().toString
    val nonce = nonceProvider()
    val updatedOptions = hawkOptions ++ Map(
      HawkOptionKeys.Ts -> Option(ts),
      HawkOptionKeys.Nonce -> Option(nonce),
      HawkOptionKeys.Ext -> Option(ext),
      HawkOptionKeys.Hash -> payloadHashOption
    ).collect { case (k, Some(v)) => k -> v }

    // Compute our MAC
    val mac = Hawk(credentials, updatedOptions, Hawk.TYPE_HEADER).mac

    // Then create our Hawk Authorization header
    val authHeader = Map(
      HawkAuthKeys.Id -> Option(credentials.id),
      HawkAuthKeys.Ts -> Option(ts),
      HawkAuthKeys.Nonce -> Option(nonce),
      HawkAuthKeys.Ext -> Option(ext),
      HawkAuthKeys.Mac -> Option(mac),
      HawkAuthKeys.Hash -> payloadHashOption
    )
      .collect({ case (k, Some(v)) => k.toString + "=" + "\"" + v + "\"" })
      .mkString(",")

    HttpHeaders.RawHeader("Authorization", s"Hawk $authHeader")
  }

  /**
   * Signs the current request using the Hawk Authentication given a user's credentials. This allows for passing of an alternative
   * timestamp and nonce generator
   *
   * @param timestampProvider Function that returns the current timestamp in seconds
   * @param nonceProvider Function that produces random strings to be used as a cryptographic nonce
   * @param ext App-specific data
   * @param credentials Credentials used to sign the request
   * @param withPayloadValidation If True, body of request is hashed amd considered when producing the Authorization header. The server will verify
   *    if the payload is valid. Passing False to this parameter will disable payload validation
   *
   * @return Transformed request with necessary Authorization headers
   */
  def addHawkCredentials(timestampProvider: TimeStampProvider, nonceProvider: NonceProvider, ext: ExtData)
                        (credentials: HawkCredentials,
                         withPayloadValidation: Boolean): RequestTransformer = { request =>
    request.mapHeaders(generateRawHeader(request,timestampProvider, nonceProvider, ext, credentials, withPayloadValidation) :: _)
  }

  /**
   * Signs the current request using the Hawk Authentication given a user's credentials. This uses the default timestamp
   * and nonce generator of the library
   *
   * @param ext App-specific data
   * @param credentials Credentials used to sign the request
   * @param withPayloadValidation If True, body of request is hashed amd considered when producing the Authorization header. The server will verify
   *    if the payload is valid. Passing False to this parameter will disable payload validation
   *
   * @return Transformed request with necessary Authorization headers
   */
  def addHawkCredentials(ext: ExtData)(credentials: HawkCredentials, withPayloadValidation: Boolean = false): RequestTransformer =
    addHawkCredentials(Util.defaultTimestampProvider, Util.defaultNonceGenerator, ext)(credentials, withPayloadValidation)

}
