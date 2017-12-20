package com.github.burkov.albLogParser

import com.google.common.net.HostAndPort
import org.junit.Assert.*
import org.junit.Test
import java.time.ZonedDateTime

class ALBLogParserTest {
    @Test
    fun fullRecordTest() {
        val sample = """
            https 2017-12-13T12:00:00.257585Z app/myservice-prod-alb/111b8011115962e 22.222.111.11:14485 11.22.3.222:32777 0.001 0.010 0.000 200 200 407 698 "GET https://account.example.com:443/myservice/rpc/doSomething.action?userId=alslrizxcvkle1235&assetId=HJKHJK2134&productCode=XY0&edition=&version=20090101&buildDate=20090101&licenseHash=2134213%2F0&salt=1235234&machineId=b66cfca2-1234-1234-1234-c01455d27c52&hostName=DESKTOP-123456.&clientVersion=4&userName=vasja&buildNumber=2009.1.1%20.107.0.20090122.120331 HTTP/1.1" "-" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:eu-west-1:111192911111:targetgroup/myservice-prod-green-service/bcf61d11d6111111 "Root=1-5a311111-21111a720161096a2222faff" "account.example.com" "arn:aws:acm:eu-west-1:917192913078:certificate/22d6d81e-1234-4321-3333-c1111f17599d"
        """.trim()

        val result = ALBLogParser.fromString(sample)
        assertNotNull(result)
        result?.apply {
            assertEquals(type, ALBRequestType.Https)
            assertEquals(timestamp, ZonedDateTime.parse("2017-12-13T12:00:00.257585Z"))
            assertEquals(elb, "app/myservice-prod-alb/111b8011115962e")
            assertEquals(client, HostAndPort.fromString("22.222.111.11:14485"))
            assertEquals(target, HostAndPort.fromString("11.22.3.222:32777"))
            assertEquals(processingTime, ALBProcessingTime(request = 0.001, target = 0.01, response = 0.0))
            assertEquals(statusCodes, ALBStatusCodes(elb = 200, target = 200))
            assertEquals(bytes, ALBBytes(rcvd = 407, sent = 698))
            assertEquals(request, ALBRequest(method = "GET", rawUrl = "https://account.example.com:443/myservice/rpc/doSomething.action?userId=alslrizxcvkle1235&assetId=HJKHJK2134&productCode=XY0&edition=&version=20090101&buildDate=20090101&licenseHash=2134213%2F0&salt=1235234&machineId=b66cfca2-1234-1234-1234-c01455d27c52&hostName=DESKTOP-123456.&clientVersion=4&userName=vasja&buildNumber=2009.1.1%20.107.0.20090122.120331", protocol = "HTTP/1.1"))
            assertEquals(userAgent, "-")
            assertEquals(sslCipher, "ECDHE-RSA-AES128-GCM-SHA256")
            assertEquals(sslProtocol, "TLSv1.2")
            assertEquals(targetGroupArn, "arn:aws:elasticloadbalancing:eu-west-1:111192911111:targetgroup/myservice-prod-green-service/bcf61d11d6111111")
            assertEquals(traceId, "Root=1-5a311111-21111a720161096a2222faff")
            assertEquals(domainName, "account.example.com")
            assertEquals(chosenCertArn, "arn:aws:acm:eu-west-1:917192913078:certificate/22d6d81e-1234-4321-3333-c1111f17599d")
        }
    }
    @Test
    fun badInputTest() {
        assertNull(ALBLogParser.fromString(""))
    }
}