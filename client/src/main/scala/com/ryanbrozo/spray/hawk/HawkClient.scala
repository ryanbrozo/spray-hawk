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

import akka.actor.ActorSystem
import akka.io.IO
import akka.pattern.ask
import spray.can.Http
import spray.client.pipelining._

import scala.compat.Platform
import scala.concurrent.Await
import scala.concurrent.duration._
import scala.util._

/**
 * Spray client example that demonstrates Hawk Authentication
 *
 */
object HawkClient extends App with HawkRequestBuilding {

  implicit val system = ActorSystem("hawk-client")

  /**
   * Execution context for futures
   */
  import system.dispatcher

  val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", MacAlgorithms.HmacSHA256)

  /**
   * Current timestamp
   */
  implicit def ts: TimeStamp = Platform.currentTime

  /**
   * Cryptographic nonce. See this Wikipedia [[http://en.wikipedia.org/wiki/Cryptographic_nonce article]]
   */
  implicit def nonce: Nonce = Random.alphanumeric.take(5).mkString

  /**
   * App-specific data
   */
  val ext: ExtData = "hawk-client"

  val pipeline =
    addHawkCredentials(hawkCreds) ~>
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
      println(s"Cannot retrieve URL: $error")
      shutdown()
  }

  def shutdown(): Unit = {
    Await.result(IO(Http).ask(Http.CloseAll)(1.second),1.second)
    system.shutdown()
  }


}
