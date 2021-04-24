const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const morgan = require('morgan')
const timeout = require('connect-timeout')
const fs = require("fs")
const fse = require('fs-extra')
const path = require("path")
var et = require('elementtree');
const app = express()
const fetch = require('node-fetch');
const ipInfo = require("ipinfo")
const Papa = require('papaparse');
const shodanClient = require('shodan-client');
const urlscan = require('urlscan-api');
const zoomRequest = require('request-promise-native');
const dns = require('dns');
const IPinfo = require("node-ipinfo");
const dmarc = require('dmarc-solution');
const captureWebsite = require('capture-website');
const clc = require('cli-color');

app.use(morgan('combined'))
app.use(bodyParser.json())
app.use(cors())
//app.use(timeout(3600000));
var server = app.listen();
//server.timeout = 60*60*100000;
app.use((req, res, next) => {
    // Set the timeout for all HTTP requests
    req.setTimeout(60*60*100000, () => {
        let err = new Error('Request Timeout');
        err.status = 408;
        next(err);
    });
    // Set the server response timeout for all HTTP requests
    res.setTimeout(60*60*100000, () => {
        let err = new Error('Service Unavailable');
        err.status = 503;
        next(err);
    });
    next();
});

const mongoose = require('mongoose');
/*const dbURI = 'mongodb+srv://' + 'admin' + ':' + 'admin' + '@clientdata.9ap6e.mongodb.net/' + 
  'ClientData' + '?retryWrites=true&w=majority';
mongoose.connect(
  dbURI, 
  {
    useNewUrlParser: true, 
    useUnifiedTopology: true
  }
)
  .then((result) => app.listen())
  .catch((error) => console.log(error));*/
const OutS11 = require('../models/outS11');
const OutS12 = require('../models/outS12');
const OutS13 = require('../models/outS13');
const OutS14 = require('../models/outS14');
const OutS15 = require('../models/outS15');
const OutS16 = require('../models/outS16');
const OutS17 = require('../models/outS17');
const OutS18 = require('../models/outS18');
const OutS19 = require('../models/outS19');
const OutS110 = require('../models/outS110');
const OutS20 = require('../models/outS20');
const OutS31 = require('../models/outS31');
const OutS32 = require('../models/outS32');
const OutS33_dubiousFiles = require('../models/outS33_dubiousFiles');
const OutS33_failConnectedFiles = require('../models/outS33_failConnectedFiles');



app.post('/output', async (req, res)=> {
  console.log("      _______________________________________________");
  console.log("     |                                               |");
  console.log("     |" + clc.green('                 Program Start                ') + " |");
  console.log("     |_______________________________________________|");
  console.log("")

  const shodanAPIKey = "RifB5RHIyi80O3BZsz3V8yUHEupjRu1T";
  const ipInfoToken = 'b3f54ca780db8a';
  const hunterAPIkey ="22850ea6e4f33099e48217886b978b65c82db488";
  const bucketsAPI = "bd44761391bfe57754976fd24172f289";

  const searchDomain = req.body.searchDomain;
  var entityName = req.body.entityName;                 
  const keyword = req.body.keyword;

  console.log("Checking existence of client database...");
  const clientDataInfo = await checkClientExist(entityName);
  const clientExists = clientDataInfo[0];
  entityName = clientDataInfo[1];
  console.log("Client exists: " + clc.green(clientExists));

  console.log("Connecting to database...");

  //Connect to mongodb
  const dbURI_2 = 'mongodb+srv://' + 'admin' + ':' + 'admin' + '@clientdata.9ap6e.mongodb.net/' + 
    entityName + '?retryWrites=true&w=majority';
  mongoose.connect(
    dbURI_2, 
    {
      useNewUrlParser: true, 
      useUnifiedTopology: true
    }
    )
    .then((result) => app.listen())
    .catch((error) => console.log(error)
  );
  await delay(10000);

  //Use the data in database if client already exists
  if (clientExists){
    var outS31;
    var outS32;
    var outS33_dubiousFile;
    var outS33_failConnected;
    var keywordLocation = -1;
 
    var dbKeywordList = await checkKeywordDataExistence(keyword);
    const keywordDataExists = dbKeywordList.includes(keyword);
    if (keywordDataExists){
      keywordLocation = getKeywordLocation(dbKeywordList, keyword);
    }
    console.log("Keyword searched before: " + clc.green(keywordDataExists));

    console.log(clc.yellowBright("OutS11: ") + "Getting subdomain of " + searchDomain);
    var subdomainData = await getOutS11FromDB();
    subdomainData = deleteIDTimeV(subdomainData);
    const t_subdomainData = tokenizeOutput(subdomainData);
    const outS11 = JSON.parse(JSON.stringify(t_subdomainData));

    console.log(clc.yellowBright("OutS12: ") + "Searching non-production entry points")
    var dataLogin = await getOutS12FromDB();
    dataLogin = deleteIDTimeV(dataLogin);
    const t_dataLogin = tokenizeOutput(dataLogin);
    const outS12 = JSON.parse(JSON.stringify(t_dataLogin));

    console.log(clc.yellowBright("OutS13: ") + "Vulnerability Scanning");
    var shodanData = await getOutS13FromDB();
    shodanData = deleteIDTimeV(shodanData);
    const t_shodanData = tokenizeOutput(shodanData);
    const outS13 = JSON.parse(JSON.stringify(t_shodanData));
    var resultShodanData = getResultShodanData(shodanData);

    console.log(clc.yellowBright("OutS14: ") + "RDP/FTP/SSH Checking");
    var shodanData2 = await getOutS14FromDB();
    shodanData2 = deleteIDTimeV(shodanData2);
    const t_shodanData2 = tokenizeOutput(shodanData2);
    const outS14 = JSON.parse(JSON.stringify(t_shodanData2));

    console.log(clc.yellowBright("OutS15: ") + "Exposed Login Portal Checking");
    var detectedData = await getOutS15FromDB();
    detectedData = deleteIDTimeV(detectedData);
    const t_detectedData = tokenizeOutput(detectedData);
    const outS15 = JSON.parse(JSON.stringify(t_detectedData));

    console.log(clc.yellowBright("OutS16: ") + "Blocking list checking");
    var botnetData = await getOutS16FromDB();
    botnetData = deleteIDTimeV(botnetData);
    const t_botnetData = tokenizeOutput(botnetData);
    const outS16 = JSON.parse(JSON.stringify(t_botnetData));

    console.log(clc.yellowBright("OutS17: ") + "Searching SPF records");
    var SPFRecordData = await getOutS17FromDB();
    SPFRecordData = deleteIDTimeV(SPFRecordData);
    const t_SPFRecordData = tokenizeOutput(SPFRecordData);
    const outS17 = JSON.parse(JSON.stringify(t_SPFRecordData));

    console.log(clc.yellowBright("OutS18: ") + "Searching DMARC records");
    var DMARCRecordData = await getOutS18FromDB();
    const outS18 = DMARCRecordData;

    console.log(clc.yellowBright("OutS19: ") + "Searching Domain Squatting");
    var immuniData = await getOutS19FromDB();
    immuniData = deleteIDTimeV(immuniData);
    const t_immuniData = tokenizeOutput(immuniData);
    const outS19 = JSON.parse(JSON.stringify(t_immuniData));

    console.log(clc.yellowBright("OutS110: ") + "TLS/SSL Certificate Analysis");
    var TLSSSLData = await getOutS110FromDB();
    TLSSSLData = deleteIDTimeV(TLSSSLData);
    const t_TLSSSLData = tokenizeOutput(TLSSSLData);
    const outS110 = JSON.parse(JSON.stringify(t_TLSSSLData));

    console.log(clc.cyanBright("OutS20: ") + "Searching emails for Social Engineering");
    var hunterIOData = await getOutS20FromDB();
    hunterIOData = deleteIDTimeV(hunterIOData);
    const t_hunterIOData = tokenizeOutput(hunterIOData);
    const outS20 = JSON.parse(JSON.stringify(t_hunterIOData));

    if (keywordDataExists){
      console.log(clc.magentaBright("OutS31: ") + "Bucket scanning");
      var cleanedBucketV3 = await getOutS31FromDB(keywordLocation);
      cleanedBucketV3 = deleteIDTimeV(cleanedBucketV3);
      cleanedBucketV3 = deleteKeyword(cleanedBucketV3);
      const t_cleanedBucket = tokenizeOutput(cleanedBucketV3);
      outS31 = JSON.parse(JSON.stringify(t_cleanedBucket));

      console.log(clc.magentaBright("OutS32: ") + "Bucket file scanning");
      var bucketFile = await getOutS32FromDB(keywordLocation);
      bucketFile = deleteIDTimeV(bucketFile);
      bucketFile = deleteKeyword(bucketFile);
      const t_bucketFile = tokenizeOutput(bucketFile);
      outS32 = JSON.parse(JSON.stringify(t_bucketFile));

      console.log(clc.magentaBright("OutS33: ") + "Dubious files checking");
      var dubiousFiles = await getOutS33_dubiousFilesFromDB(keywordLocation);
      var failConnectedFiles = await getOutS33_failConnectedFilesFromDB(keywordLocation);
      dubiousFiles = deleteIDTimeV(dubiousFiles);
      dubiousFiles = deleteKeyword(dubiousFiles);
      failConnectedFiles = deleteIDTimeV(failConnectedFiles);
      failConnectedFiles = deleteKeyword(failConnectedFiles);
      const t_dubiousFile = tokenizeOutput(dubiousFiles);
      const t_failConnected = tokenizeOutput(failConnectedFiles);
      outS33_dubiousFile = JSON.parse(JSON.stringify(t_dubiousFile));
      outS33_failConnected = JSON.parse(JSON.stringify(t_failConnected));
    }
    else{
      console.log(clc.magentaBright("OutS31: ") + "Bucket scanning");
      var grayHatWarefareBucket = await getGrayHatWarfareData(keyword, bucketsAPI);
      const cleanedBucket = cleanGrayHatWarfareData(grayHatWarefareBucket);
      const cleanedBucketV2 = await checkFiles(cleanedBucket);
      var cleanedBucketV3 = removeFailConnectAndUselessColumns(cleanedBucketV2);
      await saveOutS31(cleanedBucketV3, keyword);
      var dbKeywordList = await checkKeywordDataExistence(keyword);//
      var keywordLocation = getKeywordLocation(dbKeywordList, keyword);//
      cleanedBucketV3 = await getOutS31FromDB(keywordLocation);
      cleanedBucketV3 = deleteIDTimeV(cleanedBucketV3);
      cleanedBucketV3 = deleteKeyword(cleanedBucketV3);
      const t_cleanedBucket = tokenizeOutput(cleanedBucketV3);
      outS31 = JSON.parse(JSON.stringify(t_cleanedBucket));

      console.log(clc.magentaBright("OutS32: ") + "Bucket file scanning");
      var grayHatWarefareFile = await getGrayHatWarfareFileData(keyword, bucketsAPI);
      var grayHatWarefareFileV2 = getBucketCount(grayHatWarefareFile);
      var bucketFile = sortData(grayHatWarefareFileV2);
      await saveOutS32(bucketFile, keyword);
      bucketFile = await getOutS32FromDB(keywordLocation);
      bucketFile = deleteIDTimeV(bucketFile);
      bucketFile = deleteKeyword(bucketFile);
      const t_bucketFile = tokenizeOutput(bucketFile);
      outS32 = JSON.parse(JSON.stringify(t_bucketFile));

      console.log(clc.magentaBright("OutS33: ") + "Dubious files checking");
      const rawBucketFiles = await getBucketFiles(keyword, bucketsAPI);
      const cleanedBucketFiles = cleanRawBucketFiles(rawBucketFiles);
      const tables = await getDubiousFiles(cleanedBucketFiles);
      var dubiousFiles = tables['dubiousFiles'];
      var failConnectedFiles = tables['failConnectedFiles'];
      await saveOutS33_dubiousFiles(dubiousFiles, keyword);
      await saveOutS33_failConnetedFiles(failConnectedFiles, keyword);
      dubiousFiles = await getOutS33_dubiousFilesFromDB(keywordLocation);
      failConnectedFiles = await getOutS33_failConnectedFilesFromDB(keywordLocation);
      dubiousFiles = deleteIDTimeV(dubiousFiles);
      dubiousFiles = deleteKeyword(dubiousFiles);
      failConnectedFiles = deleteIDTimeV(failConnectedFiles);
      failConnectedFiles = deleteKeyword(failConnectedFiles);
      const t_dubiousFile = tokenizeOutput(dubiousFiles);
      const t_failConnected = tokenizeOutput(failConnectedFiles);
      outS33_dubiousFile = JSON.parse(JSON.stringify(t_dubiousFile));
      outS33_failConnected = JSON.parse(JSON.stringify(t_failConnected));
    }
    const tempScreenshotDir = __dirname.slice(0, -4) + '/uploads';
    fse.emptyDirSync(tempScreenshotDir);
    console.log("      _______________________________________________");
    console.log("     |                                               |");
    console.log("     |" + clc.green('                    Finished                  ') + " |");
    console.log("     |_______________________________________________|");
    console.log("")

    mongoose.connection.close();

    res.send({
      outS11: outS11,
      outS12: outS12,
      outS13: outS13,
      outS14: outS14,
      outS15: outS15,
      outS16: outS16,
      outS17: outS17,
      outS18: outS18,
      outS19: outS19,
      outS110: outS110,
      outS20: outS20,
      outS31: outS31,
      outS32: outS32,
      outS33_dubiousFile: outS33_dubiousFile,
      outS33_failConnected: outS33_failConnected,
    })
  }

  else{
    console.log(clc.yellowBright("OutS11: ") + "Getting subdomain of " + searchDomain)
    var subdomainData = await getSubdomains(searchDomain, ipInfoToken);
    var nsRecord = await getNSRecord(searchDomain);
    var mxRecord = await getMXRecord(searchDomain);
    var aRecord = await getARecord(searchDomain);
    var NS_MX_A_recordData = await updateRecordData(nsRecord, mxRecord, aRecord);
    subdomainData = outS11groupData(subdomainData, NS_MX_A_recordData);
    subdomainData = outS11RemoveNoInfo(subdomainData);
    subdomainData = trimData(subdomainData);
    await saveOutS11(subdomainData);
    const t_subdomainData = tokenizeOutput(subdomainData);
    const outS11 = JSON.parse(JSON.stringify(t_subdomainData));

    console.log(clc.yellowBright("OutS12: ") + "Searching non-production entry points")
    var dataLogin = getOutS12(subdomainData);
    await saveOutS12(dataLogin);
    const t_dataLogin = tokenizeOutput(dataLogin);
    const outS12 = JSON.parse(JSON.stringify(t_dataLogin));

    console.log(clc.yellowBright("OutS13: ") + "Vulnerability Scanning");
    const pendingToScan = Array.from(new Set(subdomainData['IP']));
    var shodanData = await shodanFunc(pendingToScan, shodanAPIKey);
    shodanData = trimData(shodanData);
    await saveOutS13(shodanData);
    shodanData = await getOutS13FromDB();
    shodanData = deleteIDTimeV(shodanData);
    const t_shodanData = tokenizeOutput(shodanData);
    const outS13 = JSON.parse(JSON.stringify(t_shodanData));
    var resultShodanData = getResultShodanData(shodanData);
    //var resultShodanData = getResultShodanData(shodanData);

    console.log(clc.yellowBright("OutS14: ") + "RDP/FTP/SSH Checking");
    shodanData = shodanFilterForOutS14(shodanData);
    shodanData = await shodanGetHostNameForOutS14(shodanData, ipInfoToken);//to be revised
    var shodanData2 = getShodanData2(shodanData);
    await saveOutS14(shodanData2);
    const t_shodanData2 = tokenizeOutput(shodanData2);
    const outS14 = JSON.parse(JSON.stringify(t_shodanData2));

    console.log(clc.yellowBright("OutS15: ") + "Exposed Login Portal Checking");
    var result = subdomainData;
    result = await updateResultForOutS15(result);//run through only 50 records
    var detectedData = getDetectedData(result);
    delete detectedData.Screenshot;
    await saveOutS15(detectedData);
    const t_detectedData = tokenizeOutput(detectedData);
    const outS15 = JSON.parse(JSON.stringify(t_detectedData));

    console.log(clc.yellowBright("OutS16: ") + "Blocking list checking");
    var botnetData = getFilteredDataforOutS16(subdomainData);
    console.log(clc.yellowBright("OutS16: ") + "Retrieving block list");
    var botnet = await botnetFunc();
    console.log(clc.yellowBright("OutS16: ") + "Checking potential block list in client's subdomain");
    botnetData = await updateBotnetData(botnetData, botnet);
    await saveOutS16(botnetData);
    const t_botnetData = tokenizeOutput(botnetData);
    const outS16 = JSON.parse(JSON.stringify(t_botnetData));

    console.log(clc.yellowBright("OutS17: ") + "Searching SPF records");
    const txtRecordData = await getTxtRecord(searchDomain);
    const SPFRecordData = extractSPFFromTxtRecord(txtRecordData);
    await saveOutS17(SPFRecordData);
    const t_SPFRecordData = tokenizeOutput(SPFRecordData);
    const outS17 = JSON.parse(JSON.stringify(t_SPFRecordData));

    console.log(clc.yellowBright("OutS18: ") + "Searching DMARC records");
    const DMARCRecordData = await getDMARCRecord(searchDomain);
    console.log(DMARCRecordData);
    await saveOutS18(DMARCRecordData);
    const outS18 = DMARCRecordData;

    console.log(clc.yellowBright("OutS19: ") + "Searching Domain Squatting");
    const immuniResults = await getImmuniwebData(searchDomain);
    const immuniData = extractImmuniResults(immuniResults);
    await saveOutS19(immuniData);
    const t_immuniData = tokenizeOutput(immuniData);
    const outS19 = JSON.parse(JSON.stringify(t_immuniData));

    console.log(clc.yellowBright("OutS110: ") + "TLS/SSL Certificate Analysis");
    const TLSSSLData = getTLSSSLFromOutS13(shodanData);
    await saveOutS110(TLSSSLData);
    const t_TLSSSLData = tokenizeOutput(TLSSSLData);
    const outS110 = JSON.parse(JSON.stringify(t_TLSSSLData));

    console.log(clc.cyanBright("OutS20: ") + "Searching emails for Social Engineering");
    var rawHunterIOData = await getHunterIOData(searchDomain, hunterAPIkey);
    const hunterIOData = extractHunterIOData(rawHunterIOData);
    await saveOutS20(hunterIOData);
    const t_hunterIOData = tokenizeOutput(hunterIOData);
    const outS20 = JSON.parse(JSON.stringify(t_hunterIOData));

    console.log(clc.magentaBright("OutS31: ") + "Bucket scanning");
    var grayHatWarefareBucket = await getGrayHatWarfareData(keyword, bucketsAPI);
    const cleanedBucket = cleanGrayHatWarfareData(grayHatWarefareBucket);
    const cleanedBucketV2 = await checkFiles(cleanedBucket);
    var cleanedBucketV3 = removeFailConnectAndUselessColumns(cleanedBucketV2);
    await saveOutS31(cleanedBucketV3, keyword);
    const t_cleanedBucket = tokenizeOutput(cleanedBucketV3);
    outS31 = JSON.parse(JSON.stringify(t_cleanedBucket));

    console.log(clc.magentaBright("OutS32: ") + "Bucket file scanning");
    var grayHatWarefareFile = await getGrayHatWarfareFileData(keyword, bucketsAPI);
    var grayHatWarefareFileV2 = getBucketCount(grayHatWarefareFile);
    var bucketFile = sortData(grayHatWarefareFileV2);
    await saveOutS32(bucketFile, keyword);
    const t_bucketFile = tokenizeOutput(bucketFile);
    outS32 = JSON.parse(JSON.stringify(t_bucketFile));

    console.log(clc.magentaBright("OutS33: ") + "Dubious files checking");
    const rawBucketFiles = await getBucketFiles(keyword, bucketsAPI);
    const cleanedBucketFiles = cleanRawBucketFiles(rawBucketFiles);
    const tables = await getDubiousFiles(cleanedBucketFiles);
    var dubiousFiles = tables['dubiousFiles'];
    var failConnectedFiles = tables['failConnectedFiles'];
    await saveOutS33_dubiousFiles(dubiousFiles, keyword);
    await saveOutS33_failConnetedFiles(failConnectedFiles, keyword);
    const t_dubiousFile = tokenizeOutput(dubiousFiles);
    const t_failConnected = tokenizeOutput(failConnectedFiles);
    outS33_dubiousFile = JSON.parse(JSON.stringify(t_dubiousFile));
    outS33_failConnected = JSON.parse(JSON.stringify(t_failConnected));

    console.log(clc.green("Finished!"));

    res.send({
      outS11: outS11,
      outS12: outS12,
      outS13: outS13,
      outS14: outS14,
      outS15: outS15,
      outS16: outS16,
      outS17: outS17,
      outS18: outS18,
      outS19: outS19,
      outS110: outS110,
      outS20: outS20,
      outS31: outS31,
      outS32: outS32,
      outS33_dubiousFile: outS33_dubiousFile,
      outS33_failConnected: outS33_failConnected,
    })
  }
})

app.listen(process.env.PORT || 8081)

const delay = ms => new Promise(res => setTimeout(res, ms));

/**MongoDB functions**/
async function checkClientExist(entityName){
  entityNameLower = entityName.toLowerCase();
  var allDatabasesNames = [];
  var allDatabasesNamesLower = []
  var databasesNameGet = false;
  const Admin = mongoose.mongo.Admin;

  var connection = mongoose.createConnection(
    'mongodb+srv://' + 'admin' + ':' + 'admin' + '@clientdata.9ap6e.mongodb.net/' + 
    'ClientData' + '?retryWrites=true&w=majority',
    {
      useNewUrlParser: true, 
      useUnifiedTopology: true
    }
  );
  connection.on('open', function() {
      new Admin(connection.db).listDatabases(function(err, result) {
          for (i = 0; i < result.databases.length; i++){
            allDatabasesNames.push(result.databases[i].name);
          }
          databasesNameGet = true;
          var indexDatabaseName = allDatabasesNames.indexOf("admin");
          allDatabasesNames.splice(indexDatabaseName, 1);
          indexDatabaseName = allDatabasesNames.indexOf("local");
          allDatabasesNames.splice(indexDatabaseName, 1);
          for (i = 0; i < allDatabasesNames.length; i++){
            allDatabasesNamesLower.push(allDatabasesNames[i].toLowerCase());
          }
      });
  });
  await delay(5000);

  if(allDatabasesNamesLower.includes(entityNameLower)){
    for (i = 0; i < allDatabasesNamesLower.length; i++){
      if (allDatabasesNamesLower[i] == entityNameLower)
        break;
    }
    return [true, allDatabasesNames[i]];
  }
  return [false, entityName];
}
async function checkKeywordDataExistence(keyword){
  const outS31s = await getAllInstancesOutS31();
  var dbKeywordList = [];
  for (var i = 0; i < outS31s.length; i++){
    dbKeywordList.push(outS31s[i]["Keyword"]);
  }
  return dbKeywordList;
}
async function getAllInstancesOutS31(){
  return new Promise((resolve) => {
    OutS31.find()
    .then((result) => {
      resolve(result);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
function getKeywordLocation(dbKeywordList, keyword){
  for (var i = 0; i <　dbKeywordList.length; i++){
    if (dbKeywordList[i] == keyword){
      return i;
    }
  }
  return -1;
}
/**Functions for outS11**/
async function getSubdomains(searchDomain, ipInfoToken){
    console.log(clc.yellowBright("OutS11: ") + "Getting subdomain data " + clc.green("[1/2]"));
    var url ='https://api.securitytrails.com/v1/domain/' + searchDomain + '/subdomains';
    var headers = {
      "accept": "application/json",
      "apikey": "DQBlP4wW3HFKjAA12KHc6NtiYATfTVZP",
    }
    const request_securityTrail = await fetch(url, { method: 'GET', headers: headers});
    try{
      var data = await request_securityTrail.json();
    }
    catch(err){
      console.log(clc.yellowBright("OutS11: ") + "Fail to call securityTrail!");
      var data = {'subdomain':[]};
    }
  
    if (data["subdomains"].length > 500){
      var rowCount = 500
    }
    else{
      var rowCount = data["subdomains"].length;
    }
  
    var data_v2 = {"Domain": data["subdomains"], "IP": Array(rowCount).fill("No Info"), 
      "ISP": Array(rowCount).fill("No Info"),
      "RecordType": Array(rowCount).fill("host"),
      "hostname": Array(rowCount).fill("No Info")
    };
    for (var i = 0; i < rowCount; i++) {//to be changed back
      process.stdout.write("\r\x1b[K");
      process.stdout.write(clc.yellowBright("OutS11: ") + "Working on subdomain data " + clc.green("[" + i + "/" + rowCount + "]"));
      data_v2["Domain"][i] = data_v2["Domain"][i] + "." + searchDomain;
      try{
        data_v2["IP"][i] = await getIPFunc(data_v2["Domain"][i]);
      }
      catch (err){
        process.stdout.write("\r\x1b[K");
        process.stdout.write(clc.yellowBright("OutS11: ") + "Fail to extract subdomain IP");
      }
      try{
        var tempipInfo = await ipinfoFunc(data_v2["IP"][i], ipInfoToken);
      }
      catch (err){
        process.stdout.write("\r\x1b[K");
        process.stdout.write(clc.yellowBright("OutS11: ") + "Fail to extract ISP and hostname");
        var tempipInfo = ['No Info', 'No Info'];
      }
      data_v2["ISP"][i] = tempipInfo[0];
      data_v2["hostname"][i] = tempipInfo[1];
    }
    return data_v2;
  }
  async function getIPFunc(domain){
    return new Promise((resolve, reject) => {
      dns.lookup(domain, (err, address, family) => {
          if(err) reject(err);
          resolve(address);
      });
    });
  }
  async function ipinfoFunc(ip, ipInfoToken){
    return new Promise((resolve, reject) => {
      ipInfo(ip, ipInfoToken, (err, cLoc) => {
          if(err) reject(err);
          if (cLoc.org == undefined){
            var org = "No Info";
          }
          else{
            var org = cLoc.org;
          }
          if (cLoc.country == undefined){
            var country = "No Info";
          }
          else{
            var country = cLoc.country;
          }
          if (cLoc.hostname == undefined){
            var hostname = "No Info";
          }
          else{
            var hostname = cLoc.hostname;
          }
          resolve([org + "," + country, hostname]);
      });
    });
  
  }
  async function getNSRecord(searchDomains){
    console.log("")
    console.log(clc.yellowBright("OutS11: ") + "Getting data of subdomain " + clc.green("[2/2]"));
    process.stdout.write(clc.yellowBright("OutS11: ") + "getting NS records");
    var nsRecord = {"Domain":[], "IP":[], "ISP":[], 'RecordType':[], "hostname":[]};
    const nsRecordURL = "https://www.whatsmydns.net/dns-lookup/ns-records?query=" + searchDomains + "&server=google";
    const nsRecordHTML = await getHTMLText(nsRecordURL);
    const startIndex = nsRecordHTML.indexOf(';ANSWER') + 17;
    const endIndex = nsRecordHTML.indexOf(';AUTHORITY');
    var dataString = nsRecordHTML.slice(startIndex, endIndex);
    while(dataString.includes("<strong>")){
      dataString = dataString.replace("<strong>", "");
    }
    while(dataString.includes("\n")){
      dataString = dataString.replace("\n", "");
    }
    dataString = dataString.slice(0, -10);
    const dataArrayV1 = dataString.split("</strong>");
    var dataArrayV2 = [];
    for (var i = 0; i < dataArrayV1.length; i ++){
      dataArrayV2.push(dataArrayV1[i].split(" ")[4]);
    }
    dataArrayV2 = dataArrayV2.filter(function( element ) {
      return element !== undefined;
    });
    dataArrayV2 = dataArrayV2.filter(function( element ) {
      return !(element === "");
    });
    nsRecord["Domain"] = dataArrayV2;
    nsRecord["IP"] = Array(dataArrayV2.length).fill("No Info");
    nsRecord["ISP"] = Array(dataArrayV2.length).fill("No Info");
    nsRecord["RecordType"] = Array(dataArrayV2.length).fill("dns");
    nsRecord["hostname"] = Array(dataArrayV2.length).fill("No Info");
  
    return nsRecord;
  }
  async function getMXRecord(searchDomains){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS11: ") + "getting MX records");
    var mxRecord = {"Domain":[], "IP":[], "ISP":[], 'RecordType':[], "hostname":[]};
    const nsRecordURL = "https://www.whatsmydns.net/dns-lookup/mx-records?query=" + searchDomains + "&server=google";
    const nsRecordHTML = await getHTMLText(nsRecordURL);
    const startIndex = nsRecordHTML.indexOf(';ANSWER') + 17;
    const endIndex = nsRecordHTML.indexOf(';AUTHORITY');
    var dataString = nsRecordHTML.slice(startIndex, endIndex);
    while(dataString.includes("<strong>")){
      dataString = dataString.replace("<strong>", "");
    }
    while(dataString.includes("\n")){
      dataString = dataString.replace("\n", "");
    }
    dataString = dataString.slice(0, -10);
    const dataArrayV1 = dataString.split("</strong>");
    var dataArrayV2 = [];
    for (var i = 0; i < dataArrayV1.length; i ++){
      dataArrayV2.push(dataArrayV1[i].split(" ")[5]);
    }
    dataArrayV2 = dataArrayV2.filter(function( element ) {
      return element !== undefined;
    });
    dataArrayV2 = dataArrayV2.filter(function( element ) {
      return !(element === "");
    });
    mxRecord["Domain"] = dataArrayV2;
    mxRecord["IP"] = Array(dataArrayV2.length).fill("No Info");
    mxRecord["ISP"] = Array(dataArrayV2.length).fill("No Info");
    mxRecord["RecordType"] = Array(dataArrayV2.length).fill("mx");
    mxRecord["hostname"] = Array(dataArrayV2.length).fill("No Info");
  
    return mxRecord;
  }
  async function getARecord(searchDomains){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS11: ") + "getting A records");
    var aRecord = {"Domain":[], "IP":[], "ISP":[], 'RecordType':[], "hostname":[]};
    const nsRecordURL = "https://www.whatsmydns.net/dns-lookup/a-records?query=" + searchDomains + "&server=google";
    const nsRecordHTML = await getHTMLText(nsRecordURL);
    const startIndex = nsRecordHTML.indexOf(';ANSWER') + 17;
    const endIndex = nsRecordHTML.indexOf(';AUTHORITY');
    var dataString = nsRecordHTML.slice(startIndex, endIndex);
    while(dataString.includes("<strong>")){
      dataString = dataString.replace("<strong>", "");
    }
    while(dataString.includes("\n")){
      dataString = dataString.replace("\n", "");
    }
    dataString = dataString.slice(0, -10);
    const dataArrayV1 = dataString.split("</strong>");
    var dataArrayV2 = [];
    for (var i = 0; i < dataArrayV1.length; i ++){
      dataArrayV2.push(dataArrayV1[i].split(" ")[0]);
    }
    dataArrayV2 = dataArrayV2.filter(function( element ) {
      return element !== undefined;
    });
    aRecord["Domain"] = dataArrayV2;
    aRecord["IP"] = Array(dataArrayV2.length).fill("No Info");
    aRecord["ISP"] = Array(dataArrayV2.length).fill("No Info");
    aRecord["RecordType"] = Array(dataArrayV2.length).fill("a");
    aRecord["hostname"] = Array(dataArrayV2.length).fill("No Info");
  
    return aRecord;
  }
  async function updateRecordData(nsRecord, mxRecord, aRecord){
    console.log("");
    console.log(clc.yellowBright("OutS11: ") + "Updating data of subdomain");
    records = {"Domain":[], "IP":[], "ISP":[], "RecordType":[], "hostname":[]};
    records["Domain"] = records["Domain"].concat(nsRecord["Domain"]);
    records["IP"] = records["IP"].concat(nsRecord["IP"]);
    records["ISP"] = records["ISP"].concat(nsRecord["ISP"]);
    records["RecordType"] = records["RecordType"].concat(nsRecord["RecordType"]);
    records["hostname"] = records["hostname"].concat(nsRecord["hostname"]);
    records["Domain"] = records["Domain"].concat(mxRecord["Domain"]);
    records["IP"] = records["IP"].concat(mxRecord["IP"]);
    records["ISP"] = records["ISP"].concat(mxRecord["ISP"]);
    records["RecordType"] = records["RecordType"].concat(mxRecord["RecordType"]);
    records["hostname"] = records["hostname"].concat(mxRecord["hostname"]);
    records["Domain"] = records["Domain"].concat(aRecord["Domain"]);
    records["IP"] = records["IP"].concat(aRecord["IP"]);
    records["ISP"] = records["ISP"].concat(aRecord["ISP"]);
    records["RecordType"] = records["RecordType"].concat(aRecord["RecordType"]);
    records["hostname"] = records["hostname"].concat(aRecord["hostname"]);
  
    for (var i = 0; i < records["Domain"].length; i++){
      if (records["Domain"][i].charAt(records["Domain"][i].length - 1) === "."){
        records["Domain"][i] = records["Domain"][i].slice(0, -1);
      }
      try{
        records["IP"][i] = await getIPFunc(records["Domain"][i]);
      }
      catch(err){
        process.stdout.write("\r\x1b[K");
        process.stdout.write(clc.yellowBright("OutS11: ") + "Fail to extract IP");
      }
      try{
        var tempipInfo = await ipinfoFunc(records["IP"][i]);
        records["ISP"][i] = tempipInfo[0];
        records["hostname"][i] = tempipInfo[1];
      }
      catch(err){
        process.stdout.write("\r\x1b[K");
        process.stdout.write(clc.yellowBright("OutS11: ") + "Fail to extract ISP and hostname");
      }
      process.stdout.write("\r\x1b[K");
      process.stdout.write(clc.yellowBright("OutS11: ") + "Updating data of subdomain " + 
        clc.green("[" + i + "/" + records["Domain"].length + "]"));
    }
    return records;
  }
  function outS11groupData(subdomainData, NS_MX_A_recordData){
    subdomainData['Domain'] = subdomainData['Domain'].concat(NS_MX_A_recordData['Domain']);
    subdomainData['IP'] = subdomainData['IP'].concat(NS_MX_A_recordData['IP']);
    subdomainData['ISP'] = subdomainData['ISP'].concat(NS_MX_A_recordData['ISP']);
    subdomainData['RecordType'] = subdomainData['RecordType'].concat(NS_MX_A_recordData['RecordType']);
    subdomainData['hostname'] = subdomainData['hostname'].concat(NS_MX_A_recordData['hostname']);
  
    return subdomainData;
  }
  function outS11RemoveNoInfo(subdomainData){
    for (var i = 0; i < subdomainData["Domain"].length; i++){
      if(subdomainData["IP"][i] === "No Info"){
        subdomainData["Domain"].splice(i, 1);
        subdomainData["IP"].splice(i, 1);
        subdomainData["ISP"].splice(i, 1);
        subdomainData["RecordType"].splice(i, 1);
        subdomainData["hostname"].splice(i, 1);
        i--;
      }
    }
    return subdomainData;
  }
  async function getHTMLText(domain){
    var htmlText = "";
    try{
      await fetch(domain)
      .then(res => res.text())
      .then(res => htmlText = res);
  
      return htmlText;
    }
    catch(err){
      return "Failed to Connect";
    }
  }
  function tokenizeOutput(subdomainData){
    const keys = Object.keys(subdomainData);
    var outputTokenize = [];
    if (subdomainData[keys[0]].length == 0){
      outputTokenize.push({});
      for (var j = 0; j < keys.length; j++){
        outputTokenize[0][keys[j]] = 'N/A';
      }
    }
    for (var i = 0; i < subdomainData[keys[0]].length; i++){
        outputTokenize.push({});
        for (var j = 0; j < keys.length; j++){
            outputTokenize[i][keys[j]] = subdomainData[keys[j]][i];
        }
    }
    return outputTokenize;
  }
  async function saveOutS11(data){
    const outS11Instance = new OutS11({
      Domain: data['Domain'],
      IP: data['IP'],
      ISP: data['ISP'],
      RecordType: data['RecordType'],
      hostname: data['hostname']
    });
    await outS11Instance.save()
      .then((result) => {
        console.log("");
        console.log(clc.yellowBright("OutS11: ") + "Save data success!");
      })
      .catch((err) => {
        console.log(clc.yellowBright("OutS11: ") + "Failed to save data.")
      });
  }
  async function getOutS11FromDB(){
    return new Promise((resolve) => {
      OutS11.find()
      .then((result) => {
        resolve(result[0]);
      })
      .catch((err) => {
        resolve({'No result': []});
      })
    })
  }
  function deleteIDTimeV(mongoDBData){
    var mongoDBData_ = JSON.parse(JSON.stringify(mongoDBData));
    delete mongoDBData_._id;
    delete mongoDBData_.createdAt;
    delete mongoDBData_.updatedAt;
    delete mongoDBData_.__v;

    return mongoDBData_;
  }
  function trimData(data){
    keyarr = Object.keys(data);

    if (data[keyarr[0]].length > 500){
      for (i = 0; i < keyarr.length; i++){
        data[keyarr[i]] = data[keyarr[i]].slice(0, 500);
      }
    }
    return data
  }
/**Functions for outS12**/
function getOutS12(data){
  console.log(clc.yellowBright("OutS12: ") + "Working on filtering data which contain non-production entry point keyword")
  const nonProdEntryPointList = ['dev','uat','qa','test','stag','temp','tmp'];
  var dataLogin = {"Domain":[], "IP":[], "ISP":[], "hostname": []};
  for (var i = 0; i < data['Domain'].length; i++){
    var containStr = false;
    for (var j = 0; j < nonProdEntryPointList.length; j++){
      if (data["Domain"][i].includes(nonProdEntryPointList[j])){
        containStr = true;
        break;
      }
    }
    if (containStr){
      dataLogin['Domain'].push(data['Domain'][i]);
      dataLogin['IP'].push(data['IP'][i]);
      dataLogin['ISP'].push(data['ISP'][i]);
      dataLogin['hostname'].push(data['hostname'][i]);
    }
  }
  return dataLogin;
}
async function saveOutS12(data){
  const outS12Instance = new OutS12({
    Domain: data['Domain'],
    IP: data['IP'],
    ISP: data['ISP'],
    hostname: data['hostname']
  });
  await outS12Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS12: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS12: ") + "Failed to save data.")
    });
}
async function getOutS12FromDB(){
  return new Promise((resolve) => {
    OutS12.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS13**/
async function shodanFunc(pendingToScan, shodanAPIKey){
  shodanData = {'Host':[], 'Retrieve Time':[], 'Timestamp':[], 'Port':[],
    'Protocol':[],'Organization':[],'Operating System':[],'Service':[],
    'Common Platform Enumeration ("CPE")':[],'Website Title':[],
    'Service Version':[],'HTTP Redirect':[],
    'SSL Acceptable Certification Authorities':[],
    'SSL ALPN ("Application-Layer Protocol Negotiation")':[],'SSL Cert Expired':[],
    'SSL Cert Expiration Date':[],'sSSL Cert Extensions':[],
    'SSL Cert Fingerprint in SHA1':[], 'SSL Cert Fingerprint in SHA256':[],
    'SSL Cert Issued On':[],'SSL Cert Issuer Country Name':[],
    'SSL Cert Issuer Common Name':[],'SSL Cert Issuer Locality':[],
    'SSL Cert Issuer Organization':[],'SSL Cert Issuer Organizational Unit':[],
    'SSL Cert Issuer State or Province Name':[],'SSL Cert Public Key Bits':[],
    'SSL Cert Public Key Type':[],'SSL Cert Serial':[],
    'SSL Cert Signature Algorithm':[],'SSL Cert Subject Common Name':[],
    'SSL Cert Subject Organizational Unit':[],'SSL Cert Version':[],
    'SSL Chain':[],'SSL Cipher Bits':[],'SSL Cipher Name':[],'SSL Cipher Version':[],
    'SSL TLS Extension':[],'SSL Versions':[],'Vulnerability Details':[],
    'No. Cve':[],'Highest CVSS':[],'Corresponding CVE':[]
  };
  for (i = 0; i < pendingToScan.length; i++){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS13: ") + "Working on ip " + clc.green("[" + i + "/" + pendingToScan.length + "] IP: " + pendingToScan[i]));
    await shodanFunc2(pendingToScan[i], shodanData, shodanAPIKey);
  }
  console.log("");
  return shodanData;
}
async function shodanFunc2(ip, shodanData_, shodanAPIKey){
  //const shodanAPIKey = "RifB5RHIyi80O3BZsz3V8yUHEupjRu1T";
  var host = {};
  host = await shodanFunc3(ip, shodanAPIKey);
  if (host === "No Info"){
    return;
  }
  shodanFunc4(host, shodanData_);
}
function shodanFunc3(ip, shodanAPIKey){
  return new Promise((resolve) => {
      shodanClient
      .host(ip, shodanAPIKey, history=false)
      .then(res => {
        resolve(res);
      })
      .catch(err => resolve("No Info"));
  })
}
function shodanFunc4(host, shodanData_){
  data = host.data;
  Object.entries(data).forEach(([key, instance]) => {
    nowDate = new Date();
    date = nowDate.getFullYear() + '-' + (nowDate.getMonth() + 1) + '-' + nowDate.getDate();
    time = nowDate.getHours() + ":" + nowDate.getMinutes() + ":" + nowDate.getSeconds();

    try{
      timestamp = get(instance, 'timestamp', 'None');
    }
    catch(err){
      timestamp = 'None';
    }
    curtime = date + 'T' + time;
    try{
      ip_str = get(instance, 'ip_str', 'None');
    }
    catch(err){
      ip_str = 'None';
    }
    try{
      product = get(instance, 'product', 'None');
    }
    catch(err){
      product = 'None';
    }
    try{
      shodanmodule = get(get(instance, '_shodan', ''), 'module', 'None').toString();
    }
    catch(err){
      shodanmodule = 'None';
    }
    try{
      shodanmodule_os = get(get(instance, shodanmodule, ''), 'os', 'None');
    }
    catch(err){
      shodanmodule_os = 'None';
    }
    try{
      org = get(host, 'org', 'None');
    }
    catch(err){
      org = 'None';
    }
    try{
      cpe = get(instance, 'cpe','None');
    }
    catch(err){
      cpe = 'None';
    }
    try{
      vulns = get(instance, 'cpe','None');
    }
    catch(err){
      vulns = 'None';
    }
    vulnscount= 0;

    if (typeof vulns == 'object'){
      vulnscount = vulns.length;
    }
    portvulns_all = "";
    nocve = vulnscount;
    dictcorr = {"None":0};
    cvss = 0;

    for (var j = 0; j < vulns.length; j++){
      try{
      vuln_str = vulns[i].toString();
      cvss_str = instance['vulns'][vulns[j]]['cvss'].toString();
      reference_str = instance['vulns'][vulns[j]]['references'].toString();
      summary_str = instance['vulns'][vulns[j]]['summary'].toString();
      verified_str = instance['vulns'][vulns[j]]['verified'].toString();
      
      portvulns = vuln_str + ";" + cvss_str + ";" + reference_str + ";" + summary_str + ";" + verified_str;
      dictcorr[vulns[j]] = parseFloat(instance['vulns'][vulns[j]]['cvss']);
      portvulns_all = portvulns_all + ";" + portvulns;
      }
      catch(err){}
    }
    cvss = max(dictcorr, "getValue");
    corrkey = max(dictcorr, "getKey");
    try{
      http = get(instance, 'http','None');
    }
    catch(err){
      http = 'None';
    }
    try{
      http_server = get(http, 'server','None');
    }
    catch(err){
      http_server = 'None';
    }
    try{
      http_redirects = get(http, 'redirects','None');
    }
    catch(err){
      http_redirects = 'None';
    }
    if (typeof http_redirects == 'object' && Object.keys(http_redirects).length != 0){
      http_redirects = JSON.stringify(http_redirects).slice(0, 1024);
    }
    else http_redirects = 'None';
    try{
      ssl = get(instance, 'ssl','None');
    }
    catch(err){
      ssl = 'None';
    }
    try{
      sslcert = get(ssl, 'cert','None');
    }
    catch(err){
      sslcert = 'None';
    }
    try{
      sslcertfingerprint = get(sslcert, 'fingerprint','None');
    }
    catch(err){
      sslcertfingerprint = 'None';
    }
    try{
      sslcertissuer = get(sslcert, 'issuer','None');
    }
    catch(err){
      sslcertissuer = 'None';
    }
    try{
      sslcert_pubkey = get(sslcert, 'pubkey','None');
    }
    catch(err){
      sslcert_pubkey = 'None';
    }
    try{
      sslcipher = get(ssl, 'cipher','None');
    }
    catch(err){
      sslcipher = 'None';
    }
    try{
      sslcertsubject = get(sslcert, 'subject','None');
    }
    catch(err){
      sslcertsubject = 'None';
    }
    try{
      ssl_acceptable_cas = get(ssl, 'acceptable_cas','None').toString();
    }
    catch(err){
      ssl_acceptable_cas = 'None';
    }
    if (typeof ssl_acceptable_cas == 'object' && Object.keys(ssl_acceptable_cas).length != 0){
      ssl_acceptable_cas = ssl_acceptable_cas.slice(0, 512);
    }
    else ssl_acceptable_cas = 'None';
    try{
      ssl_alpn = get(ssl, 'alpn','None');
    }
    catch(err){
      ssl_alpn = 'None';
    }
    try{
      sslcert_expired = get(sslcert, 'expired','None');
    }
    catch(err){
      sslcert_expired = 'None';
    }
    try{
      sslcert_expires = get(sslcert, 'expires','None');
    }
    catch(err){
      sslcert_expires = 'None';
    }
    try{
      sslcert_extensions = get(sslcert, 'extensions','None');
    }
    catch(err){
      sslcert_extensions = 'None';
    }
    try{
      sslcertfingerprint_sha1 = get(sslcertfingerprint, 'sha1','None');
    }
    catch(err){
      sslcertfingerprint_sha1 = 'None';
    }
    try{
      sslcertfingerprint_sha256 = get(sslcertfingerprint, 'sha256','None');
    }
    catch(err){
      sslcertfingerprint_sha256 = 'None';
    }
    try{
      sslcert_issued = get(sslcert, 'issued','None');
    }
    catch(err){
      sslcert_issued = 'None';
    }
    try{
      sslcertissuer_C = get(sslcertissuer, 'C','None');
    }
    catch(err){
      sslcertissuer_C = 'None';
    }
    try{
      sslcertissuer_CN = get(sslcertissuer, 'CN','None');
    }
    catch(err){
      sslcertissuer_CN = 'None';
    }
    try{
      sslcertissuer_L = get(sslcertissuer, 'L','None');
    }
    catch(err){
      sslcertissuer_L = 'None';
    }
    try{
      sslcertissuer_O = get(sslcertissuer, 'O','None');
    }
    catch(err){
      sslcertissuer_O = 'None';
    }
    try{
      sslcertissuer_OU = get(sslcertissuer, 'OU','None');
    }
    catch(err){
      sslcertissuer_OU = 'None';
    }
    try{
      sslcertissuer_ST = get(sslcertissuer, 'ST','None');
    }
    catch(err){
      sslcertissuer_ST = 'None';
    }
    try{
      sslcert_pubkeybits = get(sslcert_pubkey, 'bits','None');
    }
    catch(err){
      sslcert_pubkeybits = 'None';
    }
    try{
      sslcert_pubkeytype = get(sslcert_pubkey, 'type','None');
    }
    catch(err){
      sslcert_pubkeytype = 'None';
    }
    try{
      sslcert_serial = get(sslcert, 'serial','None');
    }
    catch(err){
      sslcert_serial = 'None';
    }
    try{
      sslcert_sig_alg = get(sslcert, 'sig_alg','None');
    }
    catch(err){
      sslcert_sig_alg = 'None';
    }
    try{
      sslcertsubject_CN = get(sslcertsubject, 'CN','None');
    }
    catch(err){
      sslcertsubject_CN = 'None';
    }
    try{
      sslcertsubject_OU = get(sslcertsubject, 'OU','None');
    }
    catch(err){
      sslcertsubject_OU = 'None';
    }
    try{
      sslcert_version = get(sslcert, 'version','None');
    }
    catch(err){
      sslcert_version = 'None';
    }
    try{
      ssl_chain = get(ssl, 'chain','None');
    }
    catch(err){
      ssl_chain = 'None';
    }
    try{
      sslcipher_bits = get(sslcipher, 'bits','None');
    }
    catch(err){
      sslcipher_bits = 'None';
    }
    try{
      sslcipher_name = get(sslcipher, 'name','None');
    }
    catch(err){
      sslcipher_name = 'None';
    }
    try{
      sslcipher_version = get(sslcipher, 'version','None');
    }
    catch(err){
      sslcipher_version = 'None';
    }
    try{
      ssl_tlsext = get(ssl, 'tlsext','None');
    }
    catch(err){
      ssl_tlsext = 'None';
    }
    try{
      ssl_versions = get(ssl, 'versions','None');
    }
    catch(err){
      ssl_versions = 'None';
    }

    try{ ssl_acceptable_cas = ssl_acceptable_cas.toString();}
    catch(err){ssl_acceptable_cas = 'None';}

    try{ssl_alpn = ssl_alpn.toString();}
    catch(err){ssl_alpn = 'None';}

    try{sslcert_expired = sslcert_expired.toString();}
    catch(err){sslcert_expired = 'None';}

    try{sslcert_expires = sslcert_expires.toString();}
    catch(err){sslcert_expires = 'None';}

    try{sslcert_extensions = sslcert_extensions.toString();}
    catch(err){sslcert_extensions = 'None';}

    try{sslcertfingerprint_sha1 = sslcertfingerprint_sha1.toString();}
    catch(err){sslcertfingerprint_sha1 = 'None';}

    try{sslcertfingerprint_sha256 = sslcertfingerprint_sha256.toString();}
    catch(err){sslcertfingerprint_sha256 = 'None';}

    try{sslcert_issued = sslcert_issued.toString();}
    catch(err){sslcert_issued = 'None';}

    try{sslcertissuer_C = sslcertissuer_C.toString();}
    catch(err){sslcertissuer_C = 'None';}

    try{sslcertissuer_CN = sslcertissuer_CN.toString();}
    catch(err){sslcertissuer_CN = 'None';}

    try{sslcertissuer_L = sslcertissuer_L.toString();}
    catch(err){sslcertissuer_L = 'None';}

    try{sslcertissuer_O = sslcertissuer_O.toString();}
    catch(err){sslcertissuer_O = 'None';}

    try{sslcertissuer_OU = sslcertissuer_OU.toString();}
    catch(err){sslcertissuer_OU = 'None';}

    try{sslcertissuer_ST = sslcertissuer_ST.toString();}
    catch(err){sslcertissuer_ST = 'None';}

    try{sslcert_pubkeybits = sslcert_pubkeybits.toString();}
    catch(err){sslcert_pubkeybits = 'None';}

    try{sslcert_pubkeytype = sslcert_pubkeytype.toString();}
    catch(err){sslcert_pubkeytype = 'None';}

    try{sslcert_serial = sslcert_serial.toString();}
    catch(err){sslcert_serial = 'None';}

    try{sslcert_sig_alg = sslcert_sig_alg.toString();}
    catch(err){sslcert_sig_alg = 'None';}

    try{sslcertsubject_CN = sslcertsubject_CN.toString();}
    catch(err){sslcertsubject_CN = 'None';}

    try{sslcertsubject_OU = sslcertsubject_OU.toString();}
    catch(err){sslcertsubject_OU = 'None';}

    try{sslcert_version = sslcert_version.toString();}
    catch(err){sslcert_version = 'None';}

    try{ssl_chain = ssl_chain.toString();}
    catch(err){ssl_chain = 'None';}
    try{sslcipher_bits = sslcipher_bits.toString();}
    catch(err){sslcipher_bits = 'None';}

    try{sslcipher_name = sslcipher_name.toString();}
    catch(err){sslcipher_name = 'None';}

    try{sslcipher_version = sslcipher_version.toString();}
    catch(err){sslcipher_version = 'None';}

    try{ssl_tlsext = ssl_tlsext.toString();}
    catch(err){ssl_tlsext = 'None';}

    ssl_all = ssl_acceptable_cas + "A##*_*##A" + ssl_alpn + "A##*_*##A" + sslcert_expired + 
      "A##*_*##A" + sslcert_expires + "A##*_*##A" + sslcert_extensions + "A##*_*##A" + 
      sslcertfingerprint_sha1 + "A##*_*##A" + sslcertfingerprint_sha256 + "A##*_*##A" + 
      sslcert_issued + "A##*_*##A" + sslcertissuer_C + "A##*_*##A" + sslcertissuer_CN + 
      "A##*_*##A" + sslcertissuer_L + "A##*_*##A" + sslcertissuer_O + "A##*_*##A" + 
      sslcertissuer_OU + "A##*_*##A" + sslcertissuer_ST + "A##*_*##A" + sslcert_pubkeybits + 
      "A##*_*##A" + sslcert_pubkeytype + "A##*_*##A" + sslcert_serial + "A##*_*##A" + 
      sslcert_sig_alg + "A##*_*##A" + sslcertsubject_CN + "A##*_*##A" + sslcertsubject_OU + 
      "A##*_*##A" + sslcert_version + "A##*_*##A" + ssl_chain + "A##*_*##A" + 
      sslcipher_bits + "A##*_*##A" + sslcipher_name + "A##*_*##A" + sslcipher_version + 
      "A##*_*##A" + ssl_tlsext + "A##*_*##A" + ssl_versions;
    
    http_title = get(http, 'title','None');
    try{http_title = http_title.toString();}
    catch(err){ http_title = 'None';}

    try{ip_str = ip_str.toString();}
    catch(err){ ip_str = 'None';}

    try{curtime = curtime.toString();}
    catch(err){curtime = 'None';}

    try{timestamp = timestamp.toString();}
    catch(err){timestamp = 'None';}

    try{org = org.toString();}
    catch(err){org = 'None';}

    try{shodanmodule_os = shodanmodule_os.toString();}
    catch(err){shodanmodule_os = 'None';}

    try{product = product.toString();}
    catch(err){product = 'None';}

    try{cpe = cpe.toString();}
    catch(err){cpe = 'None';}

    try{http_server = http_server.toString();}
    catch(err){http_server = 'None';}

    try{http_redirects = http_redirects.toString();}
    catch(err){http_redirects = 'None';}

    try{ssl_all = ssl_all.toString();}
    catch(err){ssl_all = 'None';}

    try{portvulns_all = portvulns_all.toString();}
    catch(err){portvulns_all = 'None';}

    try{nocve = nocve.toString();}
    catch(err){nocve = 'None';}

    try{cvss = cvss.toString();}
    catch(err){cvss = 'None';}

    try{corrkey = corrkey.toString();}
    catch(err){corrkey = 'None';}

    var str_all = ip_str + "A##*_*##A" + curtime + "A##*_*##A" + timestamp + "A##*_*##A" + 
      instance['port'].toString() + "A##*_*##A" + instance['_shodan']['module'].toString() + 
      "A##*_*##A" + org + "A##*_*##A" + shodanmodule_os + "A##*_*##A" + 
      product + "A##*_*##A" + cpe + "A##*_*##A" + http_title + "A##*_*##A" + http_server + 
      "A##*_*##A" + http_redirects + "A##*_*##A" + ssl_all + "A##*_*##A" + portvulns_all + 
      "A##*_*##A" + nocve + "A##*_*##A" + cvss + "A##*_*##A" + corrkey;
    str_all = str_all.replace('\r\n','');
    str_all = str_all.replace('\r','');
    str_all = str_all.replace('\n','');
    str_all = str_all.replace('\t','');

    var shodanKeys = Object.keys(shodanData_);
    row = str_all.split("A##*_*##A");
    for (var j = 0; j < row.length; j++){
      if (!row[j]){
        row[j] = "None";
      }
    }
    for (var j = 0; j < row.length; j++){
      shodanData_[shodanKeys[j]].push(row[j]);
    }
  });
}
function get(object, key, default_value) {
  var result = object[key];
  return (typeof result !== "undefined") ? result : default_value;
}
function max(dictcorr, getWhat){
  var keys = Object.keys(dictcorr);
  maxVal = dictcorr[keys[0]];
  maxKey = keys[0];
  for (var j = 1; j < keys.length; j++) {
    var value = dictcorr[keys[j]];
    if (value > maxVal){
      maxVal = value;
      maxKey = keys[j];
    }
  }
  if (getWhat == "getValue"){return maxVal;}
  else return maxKey;
}
function getResultShodanData(shodanData){
  resultShodanData = {Host:[],	Port:[],	WebsiteTitle:[], NoCVE:[],	HighestCVSS:[],	CorrespondingCVE:[]};
  for (var i = 0; i < shodanData.Host.length; i++){
    if (shodanData.NoCVE[i] > 0){
      resultShodanData.Host.push(shodanData.Host[i]);
      resultShodanData.Port.push(shodanData.Port[i]);
      resultShodanData.WebsiteTitle.push(shodanData.WebsiteTitle[i]);
      resultShodanData.NoCVE.push(shodanData.NoCVE[i]);
      resultShodanData.HighestCVSS.push(shodanData.HighestCVSS[i]);
      resultShodanData.CorrespondingCVE.push(shodanData.CorrespondingCVE[i]);
    }
  }
  return resultShodanData;
}
async function saveOutS13(data){
  const outS13Instance = new OutS13({
    Host: data['Host'],
    RetrieveTime: data['Retrieve Time'],
    Timestamp: data['Timestamp'],
    Port: data['Port'],
    Protocol: data['Protocol'],
    Organization: data['Organization'],
    OperatingSystem: data['Operating System'],
    Service: data['Service'],
    CommonPlatformEnumerationCPE: data['Common Platform Enumeration ("CPE")'],
    WebsiteTitle: data['Website Title'],
    ServiceVersion: data['Service Version'],
    HTTPRedirect: data['HTTP Redirect'],
    SSLAcceptableCertificationAuthorities: data['SSL Acceptable Certification Authorities'],
    SSLALPN: data['SSL ALPN ("Application-Layer Protocol Negotiation")'],
    SSLCertExpired: data['SSL Cert Expired'],
    SSLCertExpirationData: data['SSL Cert Expiration Date'],
    sSSLCertExtensions: data['sSSL Cert Extensions'],
    SSLCertFingerprintInSHA1: data['SSL Cert Fingerprint in SHA1'],
    SSLCertFingerprintInSHA256: data['SSL Cert Fingerprint in SHA256'],
    SSLCertIssuedOn: data['SSL Cert Issued On'],
    SSLCertIssuerCountryName: data['SSL Cert Issuer Country Name'],
    SSLCertIssuerCommonName: data['SSL Cert Issuer Common Name'],
    SSLCertIssuerLocality: data['SSL Cert Issuer Locality'],
    SSLCertIssuerOrganization: data['SSL Cert Issuer Organization'],
    SSLCertIssuerOrganizationalUnit: data['SSL Cert Issuer Organizational Unit'],
    SSLCertIssuerStateOrProvinceName: data['SSL Cert Issuer State or Province Name'],
    SSLCertPublicKeyBits: data['SSL Cert Public Key Bits'],
    SSLCertPublicKeyType: data['SSL Cert Public Key Type'],
    SSLCertSerial: data['SSL Cert Serial'],
    SSLCertSignatureAlgorithm: data['SSL Cert Signature Algorithm'],
    SSLCertSubjectCommonName: data['SSL Cert Subject Common Name'],
    SSLCertSubjectOrganizationalUnit: data['SSL Cert Subject Organizational Unit'],
    SSLCertVersion: data['SSL Cert Version'],
    SSLChain: data['SSL Chain'],
    SSLCipherBits: data['SSL Cipher Bits'],
    SSLCipherName: data['SSL Cipher Name'],
    SSLCipherVersion: data['SSL Cipher Version'],
    SSLTLSExtension: data['SSL TLS Extension'],
    SSLVersions: data['SSL Versions'],
    VulnerabilityDetails: data['Vulnerability Details'],
    NoCVE: data['No. Cve'],
    HighestCVSS: data['Highest CVSS'],
    CorrespondingCVE: data['Corresponding CVE']
  });
  await outS13Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS13: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS13: ") + "Failed to save data.")
    });
}
async function getOutS13FromDB(){
  return new Promise((resolve) => {
    OutS13.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS14**/
function shodanFilterForOutS14(shodanData){
  protocolKeywordList = ['ssh', 'ftp', 'rdp'];
  shodanOutS14 = {
    Host: [],RetrieveTime: [],Timestamp: [],Port: [],Protocol: [],
    Organization: [],OperatingSystem: [],Service: [],CommonPlatformEnumerationCPE: [],
    WebsiteTitle: [],ServiceVersion: [],HTTPRedirect: [],SSLAcceptableCertificationAuthorities: [],
    SSLALPN: [],SSLCertExpired: [],SSLCertExpirationData: [],sSSLCertExtensions: [],
    SSLCertFingerprintInSHA1: [],SSLCertFingerprintInSHA256: [],SSLCertIssuedOn: [],
    SSLCertIssuerCountryName: [],SSLCertIssuerCommonName: [],SSLCertIssuerLocality: [],
    SSLCertIssuerOrganization: [],SSLCertIssuerOrganizationalUnit: [],SSLCertIssuerStateOrProvinceName: [],
    SSLCertPublicKeyBits: [],SSLCertPublicKeyType: [],SSLCertSerial: [],
    SSLCertSignatureAlgorithm: [],SSLCertSubjectCommonName: [],SSLCertSubjectOrganizationalUnit: [],
    SSLCertVersion: [],SSLChain: [],SSLCipherBits: [],SSLCipherName: [],
    SSLCipherVersion: [],SSLTLSExtension: [],SSLVersions: [],VulnerabilityDetails: [],
    NoCVE: [],HighestCVSS: [],CorrespondingCVE: []
  }
  for (i = 0; i < shodanData.Host.length; i++){
    for (j = 0; j < protocolKeywordList.length; j++){
      process.stdout.write("\r\x1b[K");
      process.stdout.write("(" + i + ", " + j + ")");
      var containStr = false;
      if (shodanData.Protocol[i].includes(protocolKeywordList[j]) && shodanData.RetrieveTime[i] != "Not found"){
        containStr = true;
        break;
      }
    } 
    var shodanKeys = Object.keys(shodanData);
    if (containStr){
      for (k = 0; k < shodanKeys.length; k++){
        shodanOutS14[shodanKeys[k]].push(shodanData[shodanKeys[k]][i]);
      }
    }
  }
  console.log("");
  return shodanOutS14;
}
async function shodanGetHostNameForOutS14(shodanData, ipInfoToken){
  shodanData.HostName = [];
  for (var i = 0; i < shodanData.Host.length; i ++){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS14: ") + "Extracting host name of ip " + clc.green("[" + i + "/" + shodanData.Host.length + "]"));
    var rowHostName = await ipinfoShodanFunc(shodanData.Host[i], ipInfoToken);
    shodanData.HostName.push(rowHostName);
  }
  return shodanData;
}
async function ipinfoShodanFunc(ip, ipInfoToken){
  return new Promise((resolve, reject) => {
    ipInfo(ip, ipInfoToken, (err, cLoc) => {
        if(err) reject(err);
        var hostname;
        if (cLoc.hostname == undefined){
          var hostname = "Could Not Resolved";
        }
        else{
          hostname = cLoc.hostname;
        }
        resolve(hostname);
    });
  });
}
function getShodanData2(shodanData){
  shodanData2 = {Host:[]};
  shodanData2.Host = Array.from(shodanData.Host);
  shodanData2.Port = Array.from(shodanData.Port);
  shodanData2.Protocol = Array.from(shodanData.Protocol);
  shodanData2.Organization = Array.from(shodanData.Organization);
  shodanData2.Service = Array.from(shodanData.Service);
  shodanData2.CommonPlatformEnumerationCPE = Array.from(shodanData.CommonPlatformEnumerationCPE);
  shodanData2.VulnerabilityDetails = Array.from(shodanData.VulnerabilityDetails);
  shodanData2.NoCVE = Array.from(shodanData.NoCVE);
  shodanData2.HighestCVSS = Array.from(shodanData.HighestCVSS);
  shodanData2.CorrespondingCVE = Array.from(shodanData.CorrespondingCVE);
  shodanData2.HostName = Array.from(shodanData.HostName);
  return shodanData2;
}
async function saveOutS14(data){
  const outS14Instance = new OutS14({
    Host: data.Host,
    Port: data.Port,
    Protocol: data.Protocol,
    Organization: data.Organization,
    Service: data.Service,
    CommonPlatformEnumerationCPE: data.CommonPlatformEnumerationCPE,
    VulnerabilityDetails: data.VulnerabilityDetails,
    NoCVE: data.NoCVE,
    HighestCVSS: data.HighestCVSS,
    CorrespondingCVE: data.CorrespondingCVE,
    HostName: data.HostName
  });
  await outS14Instance.save()
    .then((result) => {
      console.log("\n")
      console.log(clc.yellowBright("OutS14: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS14: ") + "Failed to save data.")
    });
}
async function getOutS14FromDB(){
  return new Promise((resolve) => {
    OutS14.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS15**/
async function updateResultForOutS15(result){
  result.LoginPortal = [];
  result.Screenshot = [];
  var looptimes = 0;
  if (result['Domain'].length < 50)
    looptimes = result['Domain'].length;
  else
    looptimes =50;
  for (var i = 0; i < looptimes; i++){//result['Domain'].length
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS15: ") + "Working on exposed login portals " + clc.green("[" + i + "/" + looptimes + "]"));
    var planedDomain = "http://" + result['Domain'][i];
    try{
      process.stdout.write("\r\x1b[K");
      process.stdout.write(clc.yellowBright("OutS15: ") + "Getting html text " + clc.green("[" + i + "/" + looptimes + "]"));
      var htmlContent = await getHTMLText(planedDomain);
    }
    catch(err){
      htmlContent = "None";
    }
    const keyWordList = ['login', 'password', 'credentials', 'username', 'pwd', '密碼', 'pass'];
    containKeyword = checkContainKeyword(keyWordList, htmlContent);
    if (containKeyword){
      result.LoginPortal[i] = "(1) Detected";
      try{
        process.stdout.write("\r\x1b[K");
        process.stdout.write(clc.yellowBright("OutS15: ") + "Getting html screenshot " + clc.green("[" + i + "/" + looptimes + "]"));
        await getScreenshot(planedDomain, i);
        result.Screenshot[i] = i + ".png";
      }
      catch (err){
        process.stdout.write("\r\x1b[K");
        process.stdout.write(clc.yellowBright("OutS15: ") + "Fail to extract screenshoot " + clc.green("[" + i + "/" + looptimes + "]"));
        result.Screenshot[i] = "Failed to extract portal screenshot";
      }
    }
    else{
      result.LoginPortal[i] = "(0) Not Detected/Time Out";
      result.Screenshot[i] = "Failed to extract portal screenshot";
    }
  }
  console.log("");
  return result;
}
async function getHTMLText(planedDomain){
  var htmlText = "Failed to Connect";
  try{
    await fetch(planedDomain)
    .then(res => res.text())
    .then(res => htmlText = res);

    return htmlText;
  }
  catch(err){
    return htmlText;
  }
}
function checkContainKeyword(list, str){
  for (var j = 0; j < list.length; j++){
    if(str.includes(list[j])){
      return true;
    }
  }
  return false;
}
async function getScreenshot(searchDomain, i){
  try{
    await captureWebsite.file(searchDomain, i + '.png');
  }
  catch(err){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS15: ") + "Failed to extract screenshot");
  }
  /*
  const ModifiedDirName = __dirname.slice(0, -4);
  const currentPath = path.join(ModifiedDirName, i + ".png")
  const newPath = path.join(ModifiedDirName, "/uploads/" + i + ".png")
  fs.rename(currentPath, newPath, function(err) {
    if (err) {
      throw err
    }
  })*/
}
function getDetectedData(result){
  var detectedData = {Domain:[], hostname:[], IP:[], ISP:[], 
    RecordType: [], LoginPortal:[], Screenshot:[]};
  for (var i = 0; i < result.LoginPortal.length; i++){
    if (result.LoginPortal[i] == '(1) Detected'){
      detectedData.Domain.push(result.Domain[i]);
      detectedData.hostname.push(result.hostname[i]);
      detectedData.IP.push(result.IP[i]);
      detectedData.ISP.push(result.ISP[i]);
      detectedData.RecordType.push(result.RecordType[i]);
      detectedData.LoginPortal.push(result.LoginPortal[i]);
      detectedData.Screenshot.push(result.Screenshot[i]);
    }
  }
  return detectedData;
}
async function saveOutS15(data){
  const outS15Instance = new OutS15({
    Domain: data.Domain,
    IP: data.IP,
    ISP: data.ISP,
    RecordType: data.RecordType,
    hostname: data.hostname,
  });
  await outS15Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS15: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS15: ") + "Failed to save data.")
    });
}
async function getOutS15FromDB(){
  return new Promise((resolve) => {
    OutS15.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS16**/
function getFilteredDataforOutS16(data){
  var botnetData = {'Domain':[], 'IP':[]};
  botnetData['Domain'] = Array.from(data['Domain']);
  botnetData['IP'] = Array.from(data['IP']);
  return botnetData;
}
async function botnetFunc(){
  botnetURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";
  var botnet = {};
  botnet = await botnetSubFunc(botnetURL);
  return botnet;
}
function botnetSubFunc(botnetURL) {
  return new Promise((resolve, reject) => {
    Papa.parse(botnetURL, {
      download: false,
      header: false,
      comments: "#",
      complete (results) {
        resolve(results.data)
      },
      error (err) {
        reject(err)
      }
    })
  })
}
async function updateBotnetData(botnetData, botnet){
  botnetDataLength = botnetData['Domain'].length;
  botnetData['Botnet'] = Array(botnetDataLength).fill("");
  botnetData['Botnet_Details'] = Array(botnetDataLength).fill("N/A");
  botnetData['MaliciousURL'] = Array(botnetDataLength).fill("");
  botnetData['Malicious SURBL Blacklist'] = Array(botnetDataLength).fill("N/A");
  botnetData['Malicious Spamhaus Blacklist'] = Array(botnetDataLength).fill("N/A");
  botnetData['Details'] = Array(botnetDataLength).fill("N/A");
  var botnetIPs = [];
  for (var i = 0; i < botnet.length; i++){
    botnetIPs.push(botnet[i][1]);
  }
  for (var i = 0; i < botnetDataLength; i++){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.yellowBright("OutS16: ") + "Getting blacklist information " + clc.green("[" + i + "/" + botnetDataLength + "]"));
    botnetData['Botnet'][i] = botnetIPs.includes(botnetData['IP'][i]);
    var URLhaus = await urlhausFunc(botnetData['Domain'][i]);
    if (URLhaus != "N/A"){
      botnetData['MaliciousURL'][i] = URLhaus['query_status']
      if (URLhaus['query_status'] == 'ok'){
        botnetData['Malicious SURBL Blacklist'][i] = URLhaus['blacklists']['surbl'];
        botnetData['Malicious Spamhaus Blacklist'][i] = URLhaus['blacklists']['spamhaus_dbl'];
        botnetData['Details'][i] = URLhaus['blacklists']['threat'];
      }
    }
  }
  return botnetData;
}
async function urlhausFunc(domain){
  const params = new URLSearchParams();
  params.append('url', 'http://' + domain);

  urlhausURL = "https://urlhaus-api.abuse.ch/v1/url/";
  try{
    res = await fetch(urlhausURL, {method: 'POST', body: params});
    urlhausData = await res.json();
    return urlhausData;
  }
  catch(err){
    return "N/A";
  }
}
async function saveOutS16(data){
  const outS16Instance = new OutS16({
    Domain: data['Domain'],
    IP: data['IP'],
    Botnet: data['Botnet'],
    Botnet_Details: data['Botnet_Details'],
    MaliciousURL: data['MaliciousURL'],
    Malicious_SURBL_Blacklist: data['Malicious SURBL Blacklist'],
    Malicious_Spamhaus_Blacklist: data['Malicious Spamhaus Blacklist'],
    Details: data['Details']
  });
  await outS16Instance.save()
    .then((result) => {
      console.log("");
      console.log(clc.yellowBright("OutS16: ") + "Save data success!");
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS16: ") + "Failed to save data.")
    });
}
async function getOutS16FromDB(){
  return new Promise((resolve) => {
    OutS16.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS17**/
async function getTxtRecord(domain){
  return new Promise((resolve, reject) => {
    dns.resolveTxt(domain, (err, address) => {
        if(err) reject(err);
        resolve(address);
    });
  });
}
function extractSPFFromTxtRecord(txtRecordData){
  var spfRecordData = {'SPF on':[], 'Record Type': [], 'validation':[]};
  var spfIndex = -1;
  var spfArray;
  var spfArraySplited = [];
  for (i = 0; i < txtRecordData.length; i++){
    for (j = 0; j < txtRecordData[i].length; j++){
      if (txtRecordData[i][j].includes("spf")){
        spfIndex = i;
      }
    }
    if (spfIndex != -1){
      break;
    }
  }
  if (spfIndex == 1){
    return spfRecordData;
  }
  spfArray = txtRecordData[spfIndex];
  for (i = 0; i < spfArray.length; i++){
    Array.prototype.push.apply(spfArraySplited, spfArray[i].split(" "));
  }
  var spfArraySplitedLength = spfArraySplited.length;
  for (i = 0; i < spfArraySplitedLength; i++){
    if (spfArraySplited[i].includes("include") || spfArraySplited[i].includes("exists") ||
          spfArraySplited[i].includes("v=")||!spfArraySplited[i].includes(":")){
      spfArraySplited.splice(i, 1);
      spfArraySplitedLength = spfArraySplited.length;
      i--;
    }
  }
  for (i = 0; i < spfArraySplited.length; i++){
    var tempArr = spfArraySplited[i].split(":");
    spfRecordData['SPF on'].push(tempArr[1]);
    spfRecordData['Record Type'].push(tempArr[0]);
    spfRecordData['validation'].push('N/A');
  }
  return spfRecordData;
}
async function saveOutS17(data){
  const outS17Instance = new OutS17({
    SPFOn: data['SPF on'],
    RecordType: data['Record Type'],
    Validation: data['validation']
  });
  await outS17Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS17: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS17: ") + "Failed to save data.")
    });
}
async function getOutS17FromDB(){
  return new Promise((resolve) => {
    OutS17.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS18**/
async function getDMARCRecord(domain){
  var dmarcRecord;
  await dmarc.fetch(domain)
  .then(record => {
    dmarcRecord = record['record'];
  })
  .catch(err => {
    console.log(clc.yellowBright("OutS18: ") + "Failed to extract DMARC record");
    dmarcRecord = "Failed to save data.";
  });
  return dmarcRecord;
}
async function saveOutS18(data){
  const outS18Instance = new OutS18({
    record: data
  });
  await outS18Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS18: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS18: ") + "Failed to save data.")
    });
}
async function getOutS18FromDB(){
  return new Promise((resolve) => {
    OutS18.find()
    .then((result) => {
      resolve(result[0].record);
    })
    .catch((err) => {
      resolve("No record found");
    })
  })
}
/**Functions for outS19**/
async function getImmuniwebData(searchDomains){
  const UNIXStamp = Math.floor(Date.now() / 1000).toString();
  const url ='https://www.immuniweb.com/darkweb/api/v1/scan/' + UNIXStamp + '.html';
  var params1 = new URLSearchParams();
  params1.append('a', 'scan');
  params1.append('domain', searchDomains);
  params1.append('no_limit', 0);
  params1.append('dnsr', 'on');
  var request_immuni_1 = await fetch(url, { method: 'POST', body: params1});
  var DomainSquat = await request_immuni_1.json();
  if (DomainSquat.note == 'Multiple IP was resolved, select one.'){
    params1 = new URLSearchParams();
    params1.append('a', 'scan');
    params1.append('domain', searchDomains);
    params1.append('no_limit', 0);
    params1.append('dnsr', 'on');
    params1.append('choosen_ip', DomainSquat.multiple_ips[0]);
    request_immuni_1 = await fetch(url, { method: 'POST', body: params});
    DomainSquat = await request_immuni_1.json();
  }
  const url2 = 'https://www.immuniweb.com/darkweb/api/v1/get_result/' + UNIXStamp + '.html';
  const params2 = new URLSearchParams();
  params2.append('job_id', DomainSquat.job_id);
  console.log(clc.yellowBright("OutS19: ") + "Waiting Immuniweb to return result...")
  while(DomainSquat.status_id != 3){
    await delay(10000);
    request_immuni_1 = await fetch(url2, { method: 'POST', body: params2});
    DomainSquat = await request_immuni_1.json();
  }
  const url3 = 'https://www.immuniweb.com/darkweb/api/v1/get_result/' + UNIXStamp + '.html';
  const params3 = new URLSearchParams();
  params3.append('id', DomainSquat.test_id);
  var request_immuni_3 = await fetch(url3, { method: 'POST', body: params3});
  DomainS = await request_immuni_3.json();

  return DomainS.results.phishing_block4;
}
 async function getImmuniwebData1(searchDomains){
   const UNIXStamp = Math.floor(Date.now() / 1000).toString();
   const url ='https://www.immuniweb.com/radar/api/v1/scan/' + UNIXStamp + '.html';
   const params1 = new URLSearchParams();
   params1.append('a', 'scan');
   params1.append('domain', searchDomains);
   params1.append('no_limit', 0);
   params1.append('dnsr', true);
 
   var request_immuni_1 = await fetch(url, { method: 'POST', body: params1});
   var DomainSquat = await request_immuni_1.json();
 
   while(DomainSquat.status_id != 3){
     await delay(10000);
     request_immuni_1 = await fetch(url, { method: 'POST', body: params1});
     DomainSquat = await request_immuni_1.json();
   }
   const url2 = 'https://www.immuniweb.com/radar/api/v1/get_result/' + UNIXStamp + '.html';
   const params2 = new URLSearchParams();
   params2.append('id', DomainSquat.test_id);
 
   var request_immuni_2 = await fetch(url2, { method: 'POST', body: params2});
   DomainS = await request_immuni_2.json();
 
   return DomainS;
 }
function extractImmuniResults(immuniResults){
  extractedImmuniResults = {'Domain':[], 'Server IP':[], 'Fuzzer':[]};

  for (i = 0; i < immuniResults.length; i++){
    extractedImmuniResults['Domain'].push(immuniResults[i]['domain']);
    extractedImmuniResults['Server IP'].push(immuniResults[i]['server_ip']);
    extractedImmuniResults['Fuzzer'].push(immuniResults[i]['fuzzer']);
  }
  return extractedImmuniResults;
}
 async function saveOutS19(data){
  const outS19Instance = new OutS19({
    Domain: data['Domain'],
    ServerIP: data['Server IP'],
    Fuzzer: data['Fuzzer']
  });
  await outS19Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS19: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS19: ") + "Failed to save data.")
    });
}
async function getOutS19FromDB(){
  return new Promise((resolve) => {
    OutS19.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS110**/
 function getTLSSSLFromOutS13(outS13){
  TLSSSLData = {Host: [], Protocol: [], Organization: [], SSLCertIssuerCommonName: [], 
    WebsiteTitle: [],SSLCertSignatureAlgorithm: [], NoCVE: [],
    HighestCVSS: [], CorrespondingCVE: []};
  const outS13Length = outS13.Host.length;
  for (i = 0; i < outS13Length; i++){
    if (!outS13.SSLChain[i].includes('None')){
      TLSSSLData.Host.push(outS13.Host[i]);
      TLSSSLData.Protocol.push(outS13.Protocol[i]);
      TLSSSLData.Organization.push(outS13.Organization[i]);
      TLSSSLData.SSLCertIssuerCommonName.push(outS13.SSLCertIssuerCommonName[i]);
      TLSSSLData.WebsiteTitle.push(outS13.WebsiteTitle[i]);
      TLSSSLData.SSLCertSignatureAlgorithm.push(outS13.SSLCertSignatureAlgorithm[i]);
      TLSSSLData.NoCVE.push(outS13.NoCVE[i]);
      TLSSSLData.HighestCVSS.push(outS13.HighestCVSS[i]);
      TLSSSLData.CorrespondingCVE.push(outS13.CorrespondingCVE[i]);
    }
  }
  return TLSSSLData;
}
async function saveOutS110(data){
  const outS110Instance = new OutS110({
    Host: data.Host,
    Protocol: data.Protocol,
    Organization: data.Organization,
    SSLCertIssuerCommonName: data.SSLCertIssuerCommonName,
    WebsiteTitle: data.WebsiteTitle,
    SSLCertSignatureAlgorithm: data.SSLCertSignatureAlgorithm,
    NoCVE: data.NoCVE,
    HighestCVSS: data.HighestCVSS,
    CorrespondingCVE: data.CorrespondingCVE,
  });
  await outS110Instance.save()
    .then((result) => {
      console.log(clc.yellowBright("OutS110: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.yellowBright("OutS110: ") + "Failed to save data.")
    });
}
async function getOutS110FromDB(){
  return new Promise((resolve) => {
    OutS110.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS20**/
async function getHunterIOData(searchDomains, hunterAPIkey){
  //hunterAPIkey ="22850ea6e4f33099e48217886b978b65c82db488";
  url ='https://api.hunter.io/v2/domain-search?domain=' + searchDomains + '&api_key=' + hunterAPIkey + '&limit=10';
  headers = {
    "accept": "application/json",
    "apikey": hunterAPIkey
  };
  request_hunterio = await fetch(url, { method: 'GET', headers: headers}); //must include await
  hunterIOData = await request_hunterio.json(); //must include await so that will wait for data return

  return hunterIOData;
}
function extractHunterIOData(hunterIOData){
  const hunterIOKeys = Object.entries(hunterIOData);
  try{
    var emailData = hunterIOData['data']['emails'];
    var emailDataV2 = {'value':[], 'type':[], 'confidence':[], 'sources':[], 'first_name':[],
      'last_name':[], 'position':[], 'seniority':[], 'department':[], 'linkedin':[], 
      'twitter':[], 'phone_number':[], 'verification':[], 'still_in_page':[], 'LinksList':[]};
    for (i = 0; i < emailData.length; i++){
      emailDataV2['value'].push(emailData[i]['value']);
      emailDataV2['confidence'].push(emailData[i]['confidence']);
      emailDataV2['sources'].push(emailData[i]['sources']);
      emailDataV2['first_name'].push(emailData[i]['first_name']);
      emailDataV2['last_name'].push(emailData[i]['last_name']);
      emailDataV2['position'].push(emailData[i]['position']);
      emailDataV2['department'].push(emailData[i]['department']);
      emailDataV2['still_in_page'].push(false);
      emailDataV2['LinksList'].push(0);
    }
    for (i = 0; i < emailDataV2['value'].length; i++){
      var still_in_page = false;
      linkLength = 0;
      for (j = 0; j < emailDataV2['sources'][i].length; j++){
        still_in_page = still_in_page || emailDataV2['sources'][i][j]['still_on_page'];
        if (still_in_page){
          linkLength++;
        }
      }
      emailDataV2['still_in_page'][i] = still_in_page;
      emailDataV2['LinksList'][i] = linkLength;
    }
    delete emailDataV2['sources'];

    for(i = 0; i < emailDataV2['value'].length; i++){
      if (emailDataV2['position'][i] === null){
        emailDataV2['position'][i] = "None";
      }
      if (emailDataV2['department'][i] === null){
        emailDataV2['department'][i] = "None";
      }
    }

    return emailDataV2;
  }
  catch(err){
    return {};
  }
}
async function saveOutS20(data){
  const outS20Instance = new OutS20({
    Keyword: data['keyword'],
    Value: data['value'],
    Confidence: data['confidence'],
    FirstName: data['first_name'],
    LastName: data['last_name'],
    Position: data['position'],
    Department: data['department'],
    StillInPage: data['still_in_page'],
    LinksList: data['LinksList']
  });
  await outS20Instance.save()
    .then((result) => {
      console.log(clc.cyanBright("OutS20: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.cyanBright("OutS20: ") + "Failed to save data.")
    });
}
async function getOutS20FromDB(){
  return new Promise((resolve) => {
    OutS20.find()
    .then((result) => {
      resolve(result[0]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS31**/
async function getGrayHatWarfareData(keyword, bucketsAPI){
  //const bucketsAPI = "bd44761391bfe57754976fd24172f289";
  const bucketsURL = "https://buckets.grayhatwarfare.com/api/v1/buckets/0/" + 
    "2000?access_token=" + bucketsAPI + "&keywords=" + keyword;
  const headers = {
    "accept": "application/json",
    "apikey": bucketsAPI
  };
  var request_grayHat = await fetch(bucketsURL, { method: 'GET'});
  var grayHatWarfareRes = await request_grayHat.json();
  return grayHatWarfareRes['buckets'];
}
function cleanGrayHatWarfareData(grayHatWarfareData){
  var grayHatWarfareDataV2 = {'id':[], 'bucket':[], 'fileCount':[], 'type':[], 'Connection':[], 
  'PotentialFileLists': [], 'MatchedKeywordFilesCount':[]};
  for (i = 0; i < grayHatWarfareData.length; i++){
    if (grayHatWarfareData[i]['fileCount']>=1){
      grayHatWarfareDataV2['id'].push(grayHatWarfareData[i]['id']);
      grayHatWarfareDataV2['bucket'].push(grayHatWarfareData[i]['bucket']);
      grayHatWarfareDataV2['fileCount'].push(grayHatWarfareData[i]['fileCount']);
      grayHatWarfareDataV2['type'].push(grayHatWarfareData[i]['type']);
      grayHatWarfareDataV2['Connection'].push("Success");
      grayHatWarfareDataV2['PotentialFileLists'].push("");
      grayHatWarfareDataV2['MatchedKeywordFilesCount'].push(0);
    }
  }
  return grayHatWarfareDataV2;
}
async function checkFiles(cleanedBucket){
  const keyBucketWordList = ['htaccess', 'conf', 'secret', 'credential', 'password', 'broker', 'py', 'cert', 'sh','log'];
  for (var i = 0; i < cleanedBucket['id'].length; i++){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.magentaBright("OutS31: ") + "Checking potential files in buckets " + clc.green("[" + i + " / " + cleanedBucket['id'].length + "]"));
    const htmlText = await getHTMLText("http://" + cleanedBucket['bucket'][i]);
    try{
      const etree = et.parse(htmlText);
      if (etree._root.tag == "Error"){
        cleanedBucket['Connection'][i] = "Fail";
        continue;
      }
      else {
        const XMLContent = etree.findall('./Contents/Key');
        var fileList = [];
        for(var j = 0; j < XMLContent.length; j++){
          var containKeyword = false;
          for (var k = 0; k < keyBucketWordList.length; k++){
            if (XMLContent[j]['text'].includes(keyBucketWordList[k])){
              containKeyword = true;
              break;
            }
          }
          if (containKeyword){
            fileList.push(XMLContent[j]['text']);
          }
        }
        cleanedBucket['PotentialFileLists'][i] = fileList;////to string?
        cleanedBucket['MatchedKeywordFilesCount'][i] = fileList.length;
      }
    }
    catch(err){
      cleanedBucket['Connection'][i] = "Fail";
    }
  }
  return cleanedBucket;
}
async function saveOutS31(data, keyword){
  const outS31Instance = new OutS31({
    Keyword: keyword,
    Bucket: data['bucket'],
    FileCount: data['fileCount'],
    Type: data['type'],
    PotentialFileLists: data['PotentialFileLists'],
    MatchedKeywordFilesCount: data['MatchedKeywordFilesCount']
  });
  await outS31Instance.save()
    .then((result) => {
      console.log("");
      console.log(clc.magentaBright("OutS31: ") + "Save data success!");
    })
    .catch((err) => {
      console.log(clc.magentaBright("OutS31: ") + "Failed to save data.")
    });
}
async function getOutS31FromDB(keywordLocation){
  return new Promise((resolve) => {
    OutS31.find()
    .then((result) => {
      resolve(result[keywordLocation]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
function removeFailConnectAndUselessColumns(cleanedBucketV2){
  var cleanedBucketV3 = {'bucket':[], 'fileCount':[], 'type':[], 
  'PotentialFileLists': [], 'MatchedKeywordFilesCount':[]};
  for (var i = 0; i  < cleanedBucketV2['id'].length; i++){
    if(cleanedBucketV2['Connection'][i] == "Success"){
      cleanedBucketV3['bucket'].push(cleanedBucketV2['bucket'][i]);
      cleanedBucketV3['fileCount'].push(cleanedBucketV2['fileCount'][i]);
      cleanedBucketV3['type'].push(cleanedBucketV2['type'][i]);
      cleanedBucketV3['PotentialFileLists'].push(cleanedBucketV2['PotentialFileLists'][i]);
      cleanedBucketV3['MatchedKeywordFilesCount'].push(cleanedBucketV2['MatchedKeywordFilesCount'][i]);
    }
  }
  return cleanedBucketV3;
}
function deleteKeyword(keywordData){
  var keywordData_ = JSON.parse(JSON.stringify(keywordData));
  delete keywordData_.Keyword;

  return keywordData_;
}
/**Functions for outS32**/
async function getGrayHatWarfareFileData(keyword, bucketsAPI){
  //const bucketsAPI = "bd44761391bfe57754976fd24172f289";
  const bucketsURL = "https://buckets.grayhatwarfare.com/api/v1/files/" + keyword + 
    "/0/1000?access_token=" + bucketsAPI;
  const headers = {
    "accept": "application/json",
    "apikey": bucketsAPI
  };
  var fileRes = await fetch(bucketsURL, { method: 'GET', headers: headers});
  var grayHatWarfareFile = await fileRes.json();
  try{
    return grayHatWarfareFile['files'];
  }
  catch(err){
    return {};
  }
}
function getBucketCount(grayHatWarefareFile){
  var fileBucket = {'bucket':[]};
  for (i = 0; i < grayHatWarefareFile.length; i++){
    if (!fileBucket['bucket'].includes(grayHatWarefareFile[i]['bucket'])){
      fileBucket['bucket'].push(grayHatWarefareFile[i]['bucket']);
    }
  }
  fileBucket['bucketCount'] = Array(fileBucket['bucket'].length).fill(0);
  for (i = 0; i < grayHatWarefareFile.length; i++){
    bucketIndex = fileBucket['bucket'].indexOf(grayHatWarefareFile[i]['bucket']);
    fileBucket['bucketCount'][bucketIndex] += 1;
  }
  return fileBucket;
}
function sortData(grayHatWarefareFileV2){
  for (i = 0; i < grayHatWarefareFileV2['bucket'].length; i++){
    for (j = 1; i + j < grayHatWarefareFileV2['bucket'].length; j++){
      if (grayHatWarefareFileV2['bucketCount'][i + j] > grayHatWarefareFileV2['bucketCount'][i]){
        tempBucket = grayHatWarefareFileV2['bucket'][i];
        tempBucketCount = grayHatWarefareFileV2['bucketCount'][i];
        grayHatWarefareFileV2['bucket'][i] = grayHatWarefareFileV2['bucket'][i + j];
        grayHatWarefareFileV2['bucketCount'][i] = grayHatWarefareFileV2['bucketCount'][i + j];
        grayHatWarefareFileV2['bucket'][i + j] = tempBucket;
        grayHatWarefareFileV2['bucketCount'][i + j] = tempBucketCount;
      }
    }
  }
  return grayHatWarefareFileV2;
}
async function saveOutS32(data, keyword){
  const outS32Instance = new OutS32({
    Keyword: keyword,
    Bucket: data['bucket'],
    BucketCount: data['bucketCount']
  });
  await outS32Instance.save()
    .then((result) => {
      console.log(clc.magentaBright("OutS32: ") + "Save data success!")
    })
    .catch((err) => {
      console.log(clc.magentaBright("OutS32: ") + "Failed to save data.")
    });
}
async function getOutS32FromDB(keywordLocation){
  return new Promise((resolve) => {
    OutS32.find()
    .then((result) => {
      resolve(result[keywordLocation]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
/**Functions for outS33**/
async function getBucketFiles(keyword, bucketsAPI){
  //const bucketsAPI = "bd44761391bfe57754976fd24172f289";
  const bucketsURL = "https://buckets.grayhatwarfare.com/api/v1/files/" + keyword + 
    "/0/1000?access_token=" + bucketsAPI;
  const headers = {
    "accept": "application/json",
    "apikey": bucketsAPI
  };
  var fileRes = await fetch(bucketsURL, { method: 'GET', headers: headers});
  const res = await fileRes.json();
  return res['files'];
}
function cleanRawBucketFiles(rawBucketFiles){
  cleanedBucketFiles = {'filename':[], 'url':[], 'type':[]};

  for (var i = 0 ; i < rawBucketFiles.length; i++){
    cleanedBucketFiles['filename'].push(rawBucketFiles[i]['filename']);
    cleanedBucketFiles['url'].push(rawBucketFiles[i]['url']);
    cleanedBucketFiles['type'].push(rawBucketFiles[i]['type']);
  }

  return cleanedBucketFiles;
}
async function getDubiousFiles(cleanedBucketFiles){
  var tables = {
            'dubiousFiles': {'filename':[], 'url':[], 'type':[]}, 
            'failConnectedFiles': {'filename':[], 'url':[], 'type':[]}
          };
  const keyFileWordList = ['secret', 'confidential', 'htaccess', 'password', 'reset', 'procedure', 'policy','config'];

  for (i = 0; i < cleanedBucketFiles['filename'].length; i++){
    process.stdout.write("\r\x1b[K");
    process.stdout.write(clc.magentaBright("OutS33: ") + "Working on bucket file " + clc.green("[" + 
      (i + 1) + "/" + (cleanedBucketFiles['filename'].length + 1) + "]"));

    if (cleanedBucketFiles['filename'][i].includes('.png') || 
        cleanedBucketFiles['filename'][i].includes('.jpg') ||
        cleanedBucketFiles['filename'][i].includes('.webp') ||
        cleanedBucketFiles['filename'][i].includes('.svg'))
    {
      continue;
    }

    var bucketFileURL = cleanedBucketFiles['url'][i];
    var htmlText = await getHTMLText(bucketFileURL);

    if (htmlText == "Failed to Connect"){
      tables['failConnectedFiles']['filename'].push(cleanedBucketFiles['filename'][i]);
      tables['failConnectedFiles']['url'].push(cleanedBucketFiles['url'][i]);
      tables['failConnectedFiles']['type'].push(cleanedBucketFiles['type'][i]);
    }
    else{
      for (j = 0; j < keyFileWordList.length; j++){
        if (htmlText.includes(keyFileWordList[j])){
          tables['dubiousFiles']['filename'].push(cleanedBucketFiles['filename'][i]);
          tables['dubiousFiles']['url'].push(cleanedBucketFiles['url'][i]);
          tables['dubiousFiles']['type'].push(cleanedBucketFiles['type'][i]);
          break;
        }
      }
    }
  }
  return tables;
}
async function saveOutS33_dubiousFiles(data, keyword){
  const outS33_dubiousFilesInstance = new OutS33_dubiousFiles({
    Keyword: keyword,
    Filename: data['filename'],
    Url: data['url'],
    Type: data['type']
  });
  await outS33_dubiousFilesInstance.save()
    .then((result) => {
      console.log("");
      console.log(clc.magentaBright("OutS33: ") + "Save data success! " + clc.green("[1/2]"));
    })
    .catch((err) => {
      console.log(clc.magentaBright("OutS33: ") + "Failed to save data." + clc.green("[1/2]"))
    });
}
async function saveOutS33_failConnetedFiles(data, keyword){
  const outS33_failConnectedFilesInstance = new OutS33_failConnectedFiles({
    Keyword: keyword,
    Filename: data['filename'],
    Url: data['url'],
    Type: data['type']
  });
  await outS33_failConnectedFilesInstance.save()
    .then((result) => {
      console.log(clc.magentaBright("OutS33: ") + "Save data success! " + clc.green("[2/2]"));
    })
    .catch((err) => {
      console.log(clc.magentaBright("OutS33: ") + "Failed to save data." + clc.green("[2/2]"))
    });
}
async function getOutS33_dubiousFilesFromDB(keywordLocation){
  return new Promise((resolve) => {
    OutS33_dubiousFiles.find()
    .then((result) => {
      resolve(result[keywordLocation]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}
async function getOutS33_failConnectedFilesFromDB(keywordLocation){
  return new Promise((resolve) => {
    OutS33_failConnectedFiles.find()
    .then((result) => {
      resolve(result[keywordLocation]);
    })
    .catch((err) => {
      resolve({'No result': []});
    })
  })
}