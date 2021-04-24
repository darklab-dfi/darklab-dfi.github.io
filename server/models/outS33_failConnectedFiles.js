const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS33_failConnectedFilesSchema = new Schema({
    Keyword:{
        type: String,
        required: true,
    },
    Filename: {
        type: Array,
        required: true,
    },
    Url: {
        type: Array,
        required: true,
    },
    Type: {
        type: Array,
        required: true,
    }
}, {timestamps: true});

const OutS33_failConnectedFiles = mongoose.model('OutS33_failConnectedFiles', outS33_failConnectedFilesSchema);
module.exports = OutS33_failConnectedFiles;