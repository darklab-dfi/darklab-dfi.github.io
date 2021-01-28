const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS17Schema = new Schema({
    SPFOn: {
        type: Array,
        required: true,
    },
    RecordType: {
        type: Array,
        required: true,
    },
    Validation: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS17 = mongoose.model('OutS17', outS17Schema);
module.exports = OutS17;