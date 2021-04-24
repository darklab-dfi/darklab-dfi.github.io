const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS13Schema = new Schema({
    Host: {
        type: Array,
        required: true,
    },
    RetrieveTime: {
        type: Array,
        required: true,
    },
    Timestamp: {
        type: Array,
        required: true,
    },
    Port: {
        type: Array,
        required: true,
    },
    Protocol: {
        type: Array,
        required: true,
    },
    Organization: {
        type: Array,
        required: true,
    },
    OperatingSystem: {
        type: Array,
        required: true,
    },
    Service: {
        type: Array,
        required: true,
    },
    CommonPlatformEnumerationCPE: {
        type: Array,
        required: true,
    },
    WebsiteTitle: {
        type: Array,
        required: true,
    },
    ServiceVersion: {
        type: Array,
        required: true,
    },
    HTTPRedirect: {
        type: Array,
        required: true,
    },
    SSLAcceptableCertificationAuthorities: {
        type: Array,
        required: true,
    },
    SSLALPN: {
        type: Array,
        required: true,
    },
    SSLCertExpired: {
        type: Array,
        required: true,
    },
    SSLCertExpirationData: {
        type: Array,
        required: true,
    },
    sSSLCertExtensions: {
        type: Array,
        required: true,
    },
    SSLCertFingerprintInSHA1: {
        type: Array,
        required: true,
    },
    SSLCertFingerprintInSHA256: {
        type: Array,
        required: true,
    },
    SSLCertIssuedOn: {
        type: Array,
        required: true,
    },
    SSLCertIssuerCountryName: {
        type: Array,
        required: true,
    },
    SSLCertIssuerCommonName: {
        type: Array,
        required: true,
    },
    SSLCertIssuerLocality: {
        type: Array,
        required: true,
    },
    SSLCertIssuerOrganization: {
        type: Array,
        required: true,
    },
    SSLCertIssuerOrganizationalUnit: {
        type: Array,
        required: true,
    },
    SSLCertIssuerStateOrProvinceName: {
        type: Array,
        required: true,
    },
    SSLCertPublicKeyBits: {
        type: Array,
        required: true,
    },
    SSLCertPublicKeyType: {
        type: Array,
        required: true,
    },
    SSLCertSerial: {
        type: Array,
        required: true,
    },
    SSLCertSignatureAlgorithm: {
        type: Array,
        required: true,
    },
    SSLCertSubjectCommonName: {
        type: Array,
        required: true,
    },
    SSLCertSubjectOrganizationalUnit: {
        type: Array,
        required: true,
    },
    SSLCertVersion: {
        type: Array,
        required: true,
    },
    SSLChain: {
        type: Array,
        required: true,
    },
    SSLCipherBits: {
        type: Array,
        required: true,
    },
    SSLCipherName: {
        type: Array,
        required: true,
    },
    SSLCipherVersion: {
        type: Array,
        required: true,
    },
    SSLTLSExtension: {
        type: Array,
        required: true,
    },
    SSLVersions: {
        type: Array,
        required: true,
    },
    VulnerabilityDetails: {
        type: Array,
        required: true,
    },
    NoCVE: {
        type: Array,
        required: true,
    },
    HighestCVSS: {
        type: Array,
        required: true,
    },
    CorrespondingCVE: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS13 = mongoose.model('OutS13', outS13Schema);
module.exports = OutS13;