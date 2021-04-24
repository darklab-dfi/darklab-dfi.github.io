const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS32Schema = new Schema({
    Keyword:{
        type: String,
        required: true,
    },
    Bucket: {
        type: Array,
        required: true,
    },
    BucketCount: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS32 = mongoose.model('OutS32', outS32Schema);
module.exports = OutS32;