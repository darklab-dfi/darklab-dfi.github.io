const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS14Schema = new Schema({
    Host: {
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
    Service: {
        type: Array,
        required: true,
    },
    CommonPlatformEnumerationCPE: {
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
    },
    HostName: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS14 = mongoose.model('OutS14', outS14Schema);
module.exports = OutS14;