package org.eclipse.hara.ddiclient.core.api

import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okhttp3.tls.decodeCertificatePem

/**
 * Class containing data for mTLS authorization.
 * @property targetCertificate target certificate. Starts with -----BEGIN CERTIFICATE-----.
 * @property privateKey private target key.
 * @property cert server certificate. Used if server has self-signed certificate.
 */
data class HaraClientMTLSAuthData constructor(val targetCertificate: String, var privateKey: String, var cert: String? = null) {
    private val clientCertificates: HandshakeCertificates

    init {
        notEmpty(targetCertificate, "targetCertificate")
        notEmpty(privateKey, "privateKey")
        // fail fast (throw exception if certificates are bad)
        val handshakeCertificatesBuilder = HandshakeCertificates.Builder()
                .heldCertificate(HeldCertificate.decode("$targetCertificate\n$privateKey"))
        if (cert != null) {
            handshakeCertificatesBuilder.addTrustedCertificate(cert!!.decodeCertificatePem())
        } else {
            handshakeCertificatesBuilder.addPlatformTrustedCertificates()
        }
        clientCertificates = handshakeCertificatesBuilder.build()
    }

    private fun notEmpty(item: String, itemName: String) {
        if (item.isBlank()) {
            throw IllegalArgumentException("$itemName could not be null or empty")
        }
    }

    fun apply(clientBuilder: OkHttpClient.Builder) {
        clientBuilder.sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager)
    }
}