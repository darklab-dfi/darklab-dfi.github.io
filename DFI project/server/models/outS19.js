const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS19Schema = new Schema({
    Domain: {
        type: Array,
        required: true,
    },
    ServerIP: {
        type: Array,
        required: true,
    },
    Fuzzer: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS19 = mongoose.model('OutS19', outS19Schema);
module.exports = OutS19;