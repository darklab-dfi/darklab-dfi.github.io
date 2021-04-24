const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS110Schema = new Schema({
    Host: {
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
    SSLCertIssuerCommonName: {
        type: Array,
        required: true,
    },
    WebsiteTitle: {
        type: Array,
        required: true,
    },
    SSLCertSignatureAlgorithm: {
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

const OutS110 = mongoose.model('OutS110', outS110Schema);
module.exports = OutS110;