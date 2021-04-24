const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS20Schema = new Schema({
    Value: {
        type: Array,
        required: true,
    },
    Confidence: {
        type: Array,
        required: true,
    },
    FirstName: {
        type: Array,
        required: true,
    },
    LastName: {
        type: Array,
        required: true,
    },
    Position: {
        type: Array,
        required: true,
    },
    Department: {
        type: Array,
        required: true,
    },
    StillInPage: {
        type: Array,
        required: true,
    },
    LinksList: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS20 = mongoose.model('OutS20', outS20Schema);
module.exports = OutS20;