const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS12Schema = new Schema({
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
    hostname: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS12 = mongoose.model('OutS12', outS12Schema);
module.exports = OutS12;