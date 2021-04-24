const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS11Schema = new Schema({
    Domain: {
        type: Array,
        required: true,
    },
    IP: {
        type: Array,
        required: true,
    },
    ISP: {
        type: Array,
        required: true,
    },
    RecordType: {
        type: Array,
        required: true,
    },
    hostname: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS11 = mongoose.model('OutS11', outS11Schema);
module.exports = OutS11;