package com.github.burkov.jbaStats.utils

import com.google.common.net.HostAndPort
import java.io.File
import java.net.URL
import java.time.ZonedDateTime

// http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
data class ALBRequest(
        val method: String,
        val rawUrl: String,
        val protocol: String) {
    val url by lazy { URL(rawUrl) }
}

enum class ALBRequestType { Http, Https, H2, Ws, Wss }
data class ALBProcessingTime(val request: Double, val target: Double, val response: Double)
data class ALBBytes(val rcvd: Long, val sent: Long)
data class ALBStatusCodes(val elb: Int, val target: Int?)
data class ALBLogEntry(
        val type: ALBRequestType,
        val timestamp: ZonedDateTime,
        val elb: String,
        val client: HostAndPort,
        val target: HostAndPort,
        val processingTime: ALBProcessingTime,
        val statusCodes: ALBStatusCodes,
        val bytes: ALBBytes,
        val request: ALBRequest,
        val userAgent: String,
        val sslCipher: String,
        val sslProtocol: String,
        val targetGroupArn: String,
        val traceId: String,
        val domainName: String?, // nullable for backward comp
        val chosenCertArn: String?  // nullable for backward comp
)

object ALBLogParser {
    private fun String.parseALBLogEntry(): ALBLogEntry? {
        var i = 0
        fun dropWs() {
            require(i < this.length)
            while (i < this.length && this[i].isWhitespace()) i++
        }

        fun forwardTo(c: Char = '"') {
            while (this[i] != c && i < this.length) i++
            require(i < this.length)
            i++
        }

        fun String.next(c: Char = ' '): String {
            val found = this.indexOf(c, i)
            require(found > 0)
            val r = this.substring(i, found)
            i = found + 1
            return r
        }

        fun String.nextQuoted(optional: Boolean = false): String {
            if(i >= this.length && optional) return "-"
            forwardTo()
            val r = this.next('"')
            if (i < this.length)
                dropWs()
            return r
        }

        fun String.nextDouble(): Double = this.next().toDouble()
        fun String.nextInt(): Int? = this.next().toIntOrNull()
        fun String.nextLong(): Long = this.next().toLong()

        return try {
            ALBLogEntry(
                    type = ALBRequestType.valueOf(next().toLowerCase().capitalize()),
                    timestamp = ZonedDateTime.parse(next()),
                    elb = next(),
                    client = HostAndPort.fromString(next())!!,
                    target = HostAndPort.fromString(next())!!,
                    processingTime = ALBProcessingTime(nextDouble(), nextDouble(), nextDouble()),
                    statusCodes = ALBStatusCodes(nextInt()!!, nextInt()),
                    bytes = ALBBytes(nextLong(), nextLong()),
                    request = nextQuoted().parseALBRequest(),
                    userAgent = nextQuoted(),
                    sslCipher = next(),
                    sslProtocol = next(),
                    targetGroupArn = next(),
                    traceId = nextQuoted(),
                    domainName = nextQuoted(true),
                    chosenCertArn = nextQuoted(true)
            )
        } catch (e: Exception) {
            e.printStackTrace()
            println("failed to parse log line, exception: $e\nentry: $this")
            null
        }
    }

    private fun String.parseALBRequest(): ALBRequest {
        val (m, u, p) = this.split(" ")
        return ALBRequest(m, u, p)
    }

    fun fromString(string: String): ALBLogEntry? = string.parseALBLogEntry()

    fun parseFile(path: String, block: (ALBLogEntry) -> Unit) {
        File(path).forEachLine { line -> fromString(line)?.let { block(it) } }
    }
}