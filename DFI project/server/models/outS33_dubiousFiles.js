const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS33_dubiousFilesSchema = new Schema({
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

const OutS33_dubiousFiles = mongoose.model('OutS33_dubiousFiles', outS33_dubiousFilesSchema);
module.exports = OutS33_dubiousFiles;