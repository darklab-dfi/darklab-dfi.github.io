const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS16Schema = new Schema({
    Domain: {
        type: Array,
        required: true,
    },
    IP: {
        type: Array,
        required: true,
    },
    Botnet: {
        type: Array,
        required: true,
    },
    Botnet_Details: {
        type: Array,
        required: true,
    },
    MaliciousURL: {
        type: Array,
        required: true,
    },
    Malicious_SURBL_Blacklist: {
        type: Array,
        required: true,
    },
    Malicious_Spamhaus_Blacklist: {
        type: Array,
        required: true,
    },
    Details: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS16 = mongoose.model('OutS16', outS16Schema);
module.exports = OutS16;