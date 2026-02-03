'use strict';

var server = require('server');
var System = require('dw/system/System');

var jwt = require('plugin_jwt');

/**
 * Checks if the JWT test endpoints are enabled for non-production environments.
 * @returns {boolean} True when the instance is not production.
 */
function isJWTTestEnabled() {
    return System.getInstanceType() !== System.PRODUCTION_SYSTEM;
}

server.get('RSA', function (req, res, next) {
    if (!isJWTTestEnabled()) {
        res.setStatusCode(404);
        res.json({ error: 'Not Found' });
        return next();
    }

    // How to create private/public key-pair https://documentation.b2c.commercecloud.salesforce.com/DOC2/index.jsp?topic=%2Fcom.demandware.dochelp%2FDWAPI%2Fscriptapi%2Fhtml%2Fapi%2Fclass_dw_crypto_Cipher.html&resultof=%22%43%69%70%68%65%72%22%20%22%63%69%70%68%65%72%22%20&anchor=dw_crypto_Cipher_encrypt_2_String_String_String_String_Number_DetailAnchor
    var privateKey = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDG5RnOVufr0EXDvN24U0Y+nCbkCQP4uRg/Zm1uvjhevRkPvbo5Q0BjfN9biYb9IddrL0VaP7AdMrKMHIrLYrFZsntFCKbzdcd2QRlq9ECpNOCcQpcFR1kFF5ncfWfjDTn/IVMUDxcUawBleVE2Hy1VvPpG7M3wpUtBTgVgUQuIMqKowcnqokbc/dsd7Nsh5Co9ZcO4SJd2S1k0tjOlqOVWSRa2KVJpDDCoIzITzLp+wvW2CjLXOX+990QZrhTQuTYjWRQnNsW/h6NFvv6zCCGMLwdlymZXXsGBU8ha3om84hgdTpPpEiSgDDhxtwUV3+5IS+LZqYypaGFETzuT3v/jAgMBAAECggEBAIzKKa1FGWB0ip3W+H/8+pFhSapLs3MB2ucuIzKsFg0CAFaDL+pO76o8/4K1ZEeVB/8IdChBQvI4K+lAXwM/dlkPHXEtgbh+29WamVp7UbY1BvW1sV98NMiE/1Xzs3EmsLInrb5aPDUo1Rv/d3w/L4Esh2FjSRgaeZ3dk7KtS+N47I1VKR7mVAq/VISOCo+Gwsoou8w6JGDcHlotGiVBdBItuxqyrWyl/xYb7uxiPjHyuPJy+ohfS2FggANyOc4dFx/+cUHBDtt2ejycWiru5KVdKQXPdTjVM5QbbAJl7I5SfB60zrhPm6SsAXamZAA/srs0bvvEl1RDwNsfA+PLsEECgYEA7ToC+ERWW2HH3Z6H3GxTwGKnchiQILdI+97aLt804z/U9iayGTougPAy120xCZfoGgNQY3PNmAiUHfIyzUV/VOca+pVhm9d10sZe+sGf9VLWjfLRIToKXgACdpZO93NuNoK8VlZ/XA6qD9BUzprqxDOVFRZT2QjUwfCmvPtpoUMCgYEA1qKGeXd1zd01YyPaijWCieko7tAwL5C/Gci7TH6mrlacUMQZv33QapQ5aS3EayH5GWAYU+5GMymIKH/zJwGKDdbhDHk/MdbHZABlPKib6MRJZtpB3mO8Ri9FefmojC1CZtH/YRwdkFF2FD39Fg6Dctn3GLkAVp9XEFIH7wQAbOECgYBm0nwzC7u6hBlTL8GHgtSSULBvPcJKy+awdRlws4KC9UnjH0aWtKcvb+05frSAif0qOUGAudLlEOLSUAZA/tx/+mOxNUpHeA4zu5OzcHVaqfshL5wBoNyZfbuTlvbHPpsIuYXUjk1Jo3mGvS/lFTSosgruRu005yUAosRCqV5RbQKBgAhfzPleRNVkZRnaI0OzNMWmuDchHlAsyJf78frZEi3JKU4paIvFH+WYpOjKpVg8uhhYXHqh2FFUtIBIBbem4rkJgjxXWrTaGWt4bHrCZVrelbKSn3FK2OSwIXjR2damSWnzlZA3ZZvk4cOGa6J5rH1FrdNkHHREwUPcv3x+3nlhAoGADei68sA0bNhQycr6R3pMlUbKaQG8zaTU7YX3golYxgAscwuQvmUsZXYqDdo9lyl9HXjyceopq9lsQPvZqOAu0lC1LiH4yYVTTY9Ka7boBbk9dnoZTMmNEEdxFRq0ZjZfRb9MdqFNwfjukhDGADAVGnSyymtoQoEuTnZQm2xBtg4=';
    var publicKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxuUZzlbn69BFw7zduFNGPpwm5AkD+LkYP2Ztbr44Xr0ZD726OUNAY3zfW4mG/SHXay9FWj+wHTKyjByKy2KxWbJ7RQim83XHdkEZavRAqTTgnEKXBUdZBReZ3H1n4w05/yFTFA8XFGsAZXlRNh8tVbz6RuzN8KVLQU4FYFELiDKiqMHJ6qJG3P3bHezbIeQqPWXDuEiXdktZNLYzpajlVkkWtilSaQwwqCMyE8y6fsL1tgoy1zl/vfdEGa4U0Lk2I1kUJzbFv4ejRb7+swghjC8HZcpmV17BgVPIWt6JvOIYHU6T6RIkoAw4cbcFFd/uSEvi2amMqWhhRE87k97/4wIDAQAB';

    var signOptions = {
        privateKeyOrSecret: privateKey,
        algorithm: 'RS256'
    };

    var payload = {
        name: 'john',
        lastname: 'doe',
        iss: 'sample-issuer',
        sub: 'sample subject'
    };

    var jwtToken = jwt.sign(payload, signOptions);

    var decodedToken = jwt.decode(jwtToken);

    var verifyOptions = {
        publicKeyOrSecret: publicKey
    };

    var verified = jwt.verify(jwtToken, verifyOptions);

    res.json({ decodedToken: decodedToken, verified: verified, jwtToken: jwtToken });
    return next();
});

// Mini guide: generate and upload key/cert to Business Manager (Administration > Operations > Private Keys and Certificates)
// 1) Generate an RSA keypair (>= 2048 bits) and X.509 cert:
//    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-signing.key.pem
//    openssl req -new -x509 -key jwt-signing.key.pem -sha256 -days 365 \
//      -subj "/CN=jwt-signing" -out jwt-signing.cert.pem
// 2) Package private key + cert as PKCS#12 for upload (commonly accepted):
//    openssl pkcs12 -export -name jwt-signing -inkey jwt-signing.key.pem \
//      -in jwt-signing.cert.pem -out jwt-signing.p12
// 3) In BM Private Keys and Certificates, import:
//    - Private Key (from jwt-signing.p12) -> alias used by KeyRef
//    - Certificate (from jwt-signing.cert.pem) -> alias used by CertificateRef
// 4) Use those aliases in code below for signing and verification.
// Official refs: KeyRef / CertificateRef Script API
// https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_crypto_KeyRef.html
// https://documentation.b2c.commercecloud.salesforce.com/DOC2/topic/com.demandware.dochelp/DWAPI/scriptapi/html/api/class_dw_crypto_CertificateRef.html
// PKCS#12: https://www.rfc-editor.org/rfc/rfc7292
// X.509: https://www.rfc-editor.org/rfc/rfc5280
server.get('RSAKeyRef', function (req, res, next) {
    if (!isJWTTestEnabled()) {
        res.setStatusCode(404);
        res.json({ error: 'Not Found' });
        return next();
    }

    var KeyRef = require('dw/crypto/KeyRef');
    var CertificateRef = require('dw/crypto/CertificateRef');

    // Use the key/certificate aliases from Business Manager (Administration > Operations > Private Keys and Certificates).
    var privateKeyAlias = 'jwt-signing-key';
    var certificateAlias = 'jwt-signing-cert';

    var signOptions = {
        privateKeyOrSecret: new KeyRef(privateKeyAlias),
        algorithm: 'RS256',
        kid: privateKeyAlias
    };

    var payload = {
        name: 'john',
        lastname: 'doe',
        iss: 'sample-issuer',
        sub: 'sample subject'
    };

    var jwtToken = jwt.sign(payload, signOptions);
    var decodedToken = jwt.decode(jwtToken);

    var verifyOptions = {
        publicKeyOrSecret: new CertificateRef(certificateAlias)
    };

    var verified = jwt.verify(jwtToken, verifyOptions);

    res.json({ decodedToken: decodedToken, verified: verified, jwtToken: jwtToken });
    return next();
});

server.get('HMAC', function (req, res, next) {
    if (!isJWTTestEnabled()) {
        res.setStatusCode(404);
        res.json({ error: 'Not Found' });
        return next();
    }

    var secret = 'my_secret';

    var signOptions = {
        privateKeyOrSecret: secret,
        algorithm: 'HS256'
    };

    var payload = {
        name: 'john',
        lastname: 'doe',
        iss: 'sample-issuer',
        sub: 'sample subject'
    };

    var jwtToken = jwt.sign(payload, signOptions);

    var decodedToken = jwt.decode(jwtToken);

    var verifyOptions = {
        publicKeyOrSecret: secret
    };

    var verified = jwt.verify(jwtToken, verifyOptions);

    res.json({ decodedToken: decodedToken, verified: verified, jwtToken: jwtToken });
    return next();
});

module.exports = server.exports();
