const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const outS18Schema = new Schema({
    record: {
        type: String,
        required: true,
    }
}, {timestamps: true});

const OutS18 = mongoose.model('OutS18', outS18Schema);
module.exports = OutS18;