const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS15Schema = new Schema({
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

const OutS15 = mongoose.model('OutS15', outS15Schema);
module.exports = OutS15;