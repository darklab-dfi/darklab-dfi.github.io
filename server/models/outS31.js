const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS31Schema = new Schema({
    Keyword:{
        type: String,
        required: true,
    },
    Bucket: {
        type: Array,
        required: true,
    },
    FileCount: {
        type: Array,
        required: true,
    },
    Type: {
        type: Array,
        required: true,
    },
    PotentialFileLists: {
        type: Array,
        required: true,
    },
    MatchedKeywordFilesCount: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS31 = mongoose.model('OutS31', outS31Schema);
module.exports = OutS31;